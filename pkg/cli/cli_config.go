package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/cliterm"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// commitApply invokes the reconcile path for a freshly-committed config.
// Prefers the daemon's full applyConfig (single source of truth used by
// gRPC/HTTP) so D3 RSS indirection, cluster, VRRP, DHCP, etc. all
// re-converge. Falls back to the legacy applyToDataplane() when
// applyConfigFn is not wired. Warnings are non-fatal (match the prior
// applyToDataplane contract).
//
// #797 H2: worker-count changes and rss-indirection enable|disable
// committed through the in-process CLI must trigger D3 reapply; that
// only happens on the applyConfig path.
func (c *CLI) commitApply(compiled *config.Config) {
	if c.applyConfigFn != nil {
		c.applyConfigFn(compiled)
		return
	}
	if c.dp != nil {
		if err := c.applyToDataplane(compiled); err != nil {
			fmt.Fprintf(os.Stderr, "warning: dataplane apply failed: %v\n", err)
		}
	}
}

func (c *CLI) handleCopyRename(parts []string) error {
	cmd := parts[0]
	toIdx := -1
	for i, p := range parts {
		if p == "to" {
			toIdx = i
			break
		}
	}
	if toIdx < 2 || toIdx >= len(parts)-1 {
		fmt.Printf("usage: %s <src-path> to <dst-path>\n", cmd)
		return nil
	}
	srcPath := parts[1:toIdx]
	dstPath := parts[toIdx+1:]
	editPath := c.store.GetEditPath()
	if len(editPath) > 0 {
		srcPath = append(append([]string{}, editPath...), srcPath...)
		dstPath = append(append([]string{}, editPath...), dstPath...)
	}
	if cmd == "rename" {
		return c.store.Rename(srcPath, dstPath)
	}
	return c.store.Copy(srcPath, dstPath)
}

// handleInsert handles:
//
//	insert <element-path> before|after <ref-identifier>
//
// The ref-identifier (e.g., "policy allow-all") is relative to the same parent
// as the element. The full reference path is constructed by replacing the
// element's trailing identifier tokens with the ref-identifier tokens.
func (c *CLI) handleInsert(parts []string) error {
	// Find "before" or "after" keyword.
	kwIdx := -1
	isBefore := false
	for i, p := range parts {
		if p == "before" {
			kwIdx = i
			isBefore = true
			break
		}
		if p == "after" {
			kwIdx = i
			break
		}
	}
	if kwIdx < 2 || kwIdx >= len(parts)-1 {
		fmt.Println("usage: insert <element-path> before|after <ref-identifier>")
		return nil
	}
	elemPath := parts[1:kwIdx]
	refTokens := parts[kwIdx+1:]
	editPath := c.store.GetEditPath()
	if len(editPath) > 0 {
		elemPath = append(append([]string{}, editPath...), elemPath...)
	}
	// Construct the full reference path: element's parent path + ref tokens.
	// The ref tokens replace the element's trailing identifier (same keyword + name).
	if len(refTokens) > len(elemPath) {
		fmt.Println("error: reference identifier is longer than element path")
		return nil
	}
	parentPath := elemPath[:len(elemPath)-len(refTokens)]
	refPath := append(append([]string{}, parentPath...), refTokens...)
	return c.store.Insert(elemPath, refPath, isBefore)
}

// readLine reads one line of terminal input, honouring the readLineFn test
// seam. Production leaves readLineFn nil and reads from the readline instance,
// so this is the same call the console always made.
//
// The seam exists because `load ... terminal` is a security-relevant read loop
// with no other observable: the difference between a committed paste and an
// ABORTED one is invisible from outside the process, and the console's copy of
// that loop applied Ctrl-C-truncated input as complete for two years after the
// remote CLI's copy was fixed (#6548). Nothing could red, because nothing
// could drive it.
func (c *CLI) readLine() (string, error) {
	if c.readLineFn != nil {
		return c.readLineFn()
	}
	return c.rl.Readline()
}

func (c *CLI) handleLoad(args []string) error {
	if len(args) < 2 {
		fmt.Println("load:")
		fmt.Println("  override terminal    Replace candidate with pasted config")
		fmt.Println("  merge terminal       Merge pasted config into candidate")
		fmt.Println("  set terminal         Load set commands from terminal")
		fmt.Println("  override <file>      Replace candidate with file contents")
		fmt.Println("  merge <file>         Merge file contents into candidate")
		return nil
	}

	mode := args[0] // "override", "merge", or "set"
	if mode != "override" && mode != "merge" && mode != "set" {
		return fmt.Errorf("load: unknown mode %q (use 'override', 'merge', or 'set')", mode)
	}

	source := args[1]
	if mode == "set" && source != "terminal" {
		return fmt.Errorf("load set: only 'terminal' source is supported")
	}
	var content string

	if source == "terminal" {
		// Read until Ctrl-D (io.EOF) COMMITS the paste. Ctrl-C — or any other
		// read error — ABORTS it and the partial input is discarded (#6548).
		//
		// This loop used to take the same `break` for EOF, readline's
		// ErrInterrupt, and every read error, then join whatever lines had
		// been collected and apply them, printing "load <mode> complete". An
		// operator who aborted a paste was told it had succeeded and could
		// commit a TRUNCATED configuration — and a truncated `security
		// policies` stanza is a WIDENED one, because the deny terms that would
		// have followed never arrive.
		//
		// #4883-D fixed exactly this on the REMOTE CLI and was never applied
		// here. The loop now lives in pkg/cliterm so there is one
		// implementation for both surfaces rather than two copies to keep in
		// step — the divergence is what produced this bug.
		fmt.Println("[Type or paste configuration, then press Ctrl-D on an empty line]")
		var err error
		content, err = cliterm.ReadConfig(c.readLine)
		if err != nil {
			return err
		}
	} else {
		// Read from file
		// #6753: bound the READ, not just the post-read length. checkConfigSize
		// takes an already-materialised string, so it bounds what the store
		// ACCEPTS, never what this path ALLOCATES.
		data, err := configstore.ReadBoundedConfigFile(source)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		content = string(data)
	}

	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("load: empty input")
	}

	// #9892: adjudicate the CONTENT against the class's deny-configuration
	// regexes, HERE and not at dispatch.
	//
	// cli_dispatch.go DOES run checkConfigRegex on every config-mode line,
	// including this one — but it delegates to configMutationPath, which
	// returns ok=false for any verb outside configMutationVerbs, and `load` is
	// not in that map. So the gate executed and declined to adjudicate, which
	// is worse than being absent: a reader auditing that path sees a gate on
	// it. And it could not have done better there, because at dispatch time
	// the content has not been read yet — `terminal` input arrives only after
	// the paste completes, several lines below.
	//
	// Same evaluator as the REST and gRPC surfaces (pkg/config), not an
	// equivalent copy: two renderings of hierarchical content as set lines
	// drift, and each looks right on its own.
	var loadCfg *config.Config
	if c.store != nil {
		loadCfg = c.store.ActiveConfig()
	}
	if err := config.AuthorizeConfigLoad(loadCfg, c.userClass, mode, content); err != nil {
		return err
	}

	switch mode {
	case "set":
		count, err := c.store.LoadSet(content)
		if err != nil {
			return fmt.Errorf("load set: %w", err)
		}
		fmt.Printf("load set complete: %d commands applied\n", count)
		return nil
	default:
		var err error
		switch mode {
		case "override":
			err = c.store.LoadOverride(content)
		case "merge":
			err = c.store.LoadMerge(content)
		}
		if err != nil {
			return fmt.Errorf("load %s: %w", mode, err)
		}
		fmt.Printf("load %s complete\n", mode)
		return nil
	}
}

func (c *CLI) handleCommit(args []string) error {
	if len(args) > 0 && args[0] == "check" {
		compiled, err := c.store.CommitCheck()
		if err != nil {
			return fmt.Errorf("commit check failed: %w", err)
		}
		printConfigWarnings(compiled.Warnings)
		fmt.Println("configuration check succeeds")
		return nil
	}

	if len(args) > 0 && args[0] == "comment" {
		if len(args) < 2 {
			return fmt.Errorf("usage: commit comment \"description\"")
		}
		desc := commitCommentFromArgs(args[1:])

		diffSummary := c.store.CommitDiffSummary()

		compiled, err := c.runCommit(desc)
		if err != nil {
			return fmt.Errorf("commit failed: %w", err)
		}

		c.reloadSyslog(compiled)
		c.refreshPrompt()

		printConfigWarnings(compiled.Warnings)
		if diffSummary != "" {
			fmt.Printf("commit complete: %s\n", diffSummary)
		} else {
			fmt.Println("commit complete")
		}
		return nil
	}

	if len(args) > 0 && args[0] == "confirmed" {
		if len(args) > 2 {
			return fmt.Errorf("usage: commit confirmed [minutes]")
		}
		// #4868: `commit confirmed` is the operator's rollback guard, so a
		// malformed/out-of-range timeout must ERROR rather than silently arm the
		// 10-minute default (banana|0|-1) or truncate a large value. Parse into
		// the int32/Junos range and enforce [1, MaxCommitConfirmedMinutes].
		minutes := 10
		if len(args) >= 2 {
			v, err := strconv.ParseInt(args[1], 10, 32)
			if err != nil || v <= 0 {
				return fmt.Errorf("commit confirmed: invalid timeout %q "+
					"(want a positive number of minutes, 1..%d)", args[1], configstore.MaxCommitConfirmedMinutes)
			}
			if v > configstore.MaxCommitConfirmedMinutes {
				return fmt.Errorf("commit confirmed: timeout %d exceeds maximum %d minutes",
					v, configstore.MaxCommitConfirmedMinutes)
			}
			minutes = int(v)
		}

		compiled, err := c.runCommitConfirmed(minutes)
		if err != nil {
			return fmt.Errorf("commit confirmed failed: %w", err)
		}

		c.reloadSyslog(compiled)
		c.refreshPrompt()

		printConfigWarnings(compiled.Warnings)
		fmt.Printf("commit confirmed will be automatically rolled back in %d minutes unless confirmed\n", minutes)
		return nil
	}

	// #4868: an unrecognized first token (e.g. the typo `commit confimed 10`)
	// must NOT fall through to the permanent commit below — that would be a
	// management-stranding change with no rollback timer. Reject it before any
	// mutation. Valid modifiers mirror cmdtree (check / comment / confirmed).
	if len(args) > 0 {
		return fmt.Errorf("commit: unknown option %q (valid: check, comment, confirmed)", args[0])
	}

	// Bare commit during a pending commit-confirmed window (#4000). Junos
	// semantics: a `commit` here confirms the pending config AND commits any
	// new candidate edits. If the candidate is UNCHANGED since the pending
	// commit, this is a pure confirmation — cancel the rollback timer, no new
	// commit (avoids a spurious history/rollback entry). If the operator
	// staged NEW edits after `commit confirmed`, fall through to the normal
	// commit below: CommitWithDescription (#3861) applies the new candidate
	// AND clears the confirm timer, so the edits are committed rather than
	// silently dropped (the pre-#4000 intercept confirmed-and-discarded).
	if c.store.IsConfirmPending() && !c.store.IsDirty() {
		if err := c.store.ConfirmCommit(); err != nil {
			return fmt.Errorf("confirm commit: %w", err)
		}
		fmt.Println("commit confirmed")
		return nil
	}

	// Capture diff summary before commit (active will change)
	diffSummary := c.store.CommitDiffSummary()

	compiled, err := c.runCommit("")
	if err != nil {
		return fmt.Errorf("commit failed: %w", err)
	}

	// Hot-reload syslog clients
	c.reloadSyslog(compiled)
	c.refreshPrompt()

	printConfigWarnings(compiled.Warnings)
	if diffSummary != "" {
		fmt.Printf("commit complete: %s\n", diffSummary)
	} else {
		fmt.Println("commit complete")
	}
	return nil
}

func printConfigWarnings(warnings []string) {
	for _, warning := range warnings {
		fmt.Printf("warning: %s\n", warning)
	}
}

// runCommit dispatches to the daemon's atomic commit+apply when
// wired (#846); otherwise falls back to store.Commit followed by
// commitApply (the legacy path used by standalone CLI without a
// daemon). The atomic path serializes against HTTP/gRPC/event-engine
// commits via d.applySem.
//
// Uses a cancellable context registered with the CLI's Ctrl-C
// handler so an operator can interrupt a commit that's hung
// waiting for the apply lock (e.g. a long-running peer-sync apply
// holding it).
func (c *CLI) runCommit(comment string) (*config.Config, error) {
	if c.commitFn != nil {
		ctx, done := c.commitCtx()
		defer done()
		return c.commitFn(ctx, comment)
	}
	var compiled *config.Config
	var err error
	if comment != "" {
		compiled, err = c.store.CommitWithDescription(comment)
	} else {
		compiled, err = c.store.Commit()
	}
	if err != nil {
		return nil, err
	}
	c.commitApply(compiled)
	return compiled, nil
}

// runCommitConfirmed is the commit-confirmed analogue of runCommit.
func (c *CLI) runCommitConfirmed(minutes int) (*config.Config, error) {
	if c.commitConfirmedFn != nil {
		ctx, done := c.commitCtx()
		defer done()
		return c.commitConfirmedFn(ctx, minutes)
	}
	compiled, err := c.store.CommitConfirmed(minutes)
	if err != nil {
		return nil, err
	}
	c.commitApply(compiled)
	return compiled, nil
}

// commitCtx returns a cancellable context registered with the CLI's
// Ctrl-C handler via the dedicated commitCancel slot (separate from
// cmdCancel which is used by external commands). Single-writer per
// call site means the cleanup can clear unconditionally — the slot
// is only ever set/cleared by a runCommit pair. The returned `done`
// MUST be deferred by the caller.
func (c *CLI) commitCtx() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	c.cmdMu.Lock()
	c.commitCancel = cancel
	c.cmdMu.Unlock()
	return ctx, func() {
		c.cmdMu.Lock()
		c.commitCancel = nil
		c.cmdMu.Unlock()
		cancel()
	}
}

// #1044c Phase 1: handleConfigShow relocated from cli.go (no behavior change).
func (c *CLI) handleConfigShow(args []string) error {
	// Check for pipe commands
	line := strings.Join(args, " ")

	// Secret redaction (#4099): route the config-mode config display through
	// the #4051 *Redacted store methods for a login class that
	// showConfigRedacted() flags. Config mode requires PermConfig (super-user
	// today), so this is defense-in-depth — cleartext for the current
	// reachable class, and automatically masked should a non-super-user ever
	// gain config-view access. The redacted candidate variants take the path
	// directly (nil/empty == whole tree) and mirror the cleartext siblings'
	// nil-source defaults.
	redact := c.showConfigRedacted()

	if strings.Contains(line, "| compare") {
		// Check for "| compare rollback N"
		if idx := strings.Index(line, "| compare rollback"); idx >= 0 {
			rest := strings.TrimSpace(line[idx+len("| compare rollback"):])
			n, err := strconv.Atoi(rest)
			if err != nil || n < 1 {
				return fmt.Errorf("usage: show | compare rollback <N>")
			}
			var diff string
			if redact {
				diff, err = c.store.ShowCompareRollbackRedacted(n)
			} else {
				diff, err = c.store.ShowCompareRollback(n)
			}
			if err != nil {
				return err
			}
			fmt.Print(diff)
			return nil
		}
		if redact {
			fmt.Print(c.store.ShowCompareRedacted())
		} else {
			fmt.Print(c.store.ShowCompare())
		}
		return nil
	}

	// Build path from editPath + args before the pipe (used by all formats).
	var displayPath []string
	{
		editPath := c.store.GetEditPath()
		displayPath = append(displayPath, editPath...)
		for _, a := range args {
			if a == "|" {
				break
			}
			displayPath = append(displayPath, a)
		}
	}

	var output string
	switch {
	case strings.Contains(line, "| display json"):
		switch {
		case redact:
			output = c.store.ShowCandidateJSONRedacted(displayPath)
		case len(displayPath) > 0:
			output = c.store.ShowCandidatePathJSON(displayPath)
		default:
			output = c.store.ShowCandidateJSON()
		}
	case strings.Contains(line, "| display set"):
		switch {
		case redact:
			output = c.store.ShowCandidateSetRedacted(displayPath)
		case len(displayPath) > 0:
			output = c.store.ShowCandidatePathSet(displayPath)
		default:
			output = c.store.ShowCandidateSet()
		}
	case strings.Contains(line, "| display xml"):
		switch {
		case redact:
			output = c.store.ShowCandidateXMLRedacted(displayPath)
		case len(displayPath) > 0:
			output = c.store.ShowCandidatePathXML(displayPath)
		default:
			output = c.store.ShowCandidateXML()
		}
	case strings.Contains(line, "| display inheritance"):
		switch {
		case redact:
			output = c.store.ShowCandidateInheritanceRedacted(displayPath)
		case len(displayPath) > 0:
			output = c.store.ShowCandidatePathInheritance(displayPath)
		default:
			output = c.store.ShowCandidateInheritance()
		}
	case strings.Index(line, "| ") >= 0:
		// Unknown pipe command
		idx := strings.Index(line, "| ")
		pipeParts := strings.Fields(strings.TrimSpace(line[idx+2:]))
		if len(pipeParts) >= 2 && pipeParts[0] == "display" {
			fmt.Printf("syntax error: unknown display option '%s'\n", pipeParts[1])
		} else if len(pipeParts) > 0 {
			fmt.Printf("syntax error: unknown pipe command '%s'\n", pipeParts[0])
		}
		return nil
	default:
		// Show scoped to path (editPath + args), or the whole candidate.
		switch {
		case redact:
			output = c.store.ShowCandidateRedacted(displayPath)
		case len(displayPath) > 0:
			output = c.store.ShowCandidatePath(displayPath)
		default:
			output = c.store.ShowCandidate()
		}
	}
	if len(displayPath) > 0 && output == "" {
		fmt.Printf("configuration path not found: %s\n", strings.Join(displayPath, " "))
	} else {
		fmt.Print(output)
	}
	return nil
}
