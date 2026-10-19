package cli

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cliterm"
	"github.com/psaab/xpf/pkg/config"
)

var errExit = fmt.Errorf("exit")

// localConfigSessionID is the config-lock holder identity the in-process
// CLI stamps on its own configure/configure-exclusive acquisition (#14986).
// Every other surface carries a peer/session holder; the console used to
// acquire with "" / "cli", which effectiveHolderLocked could not tell
// apart from the internal/system bypass and from another holder's lock.
const localConfigSessionID = "local-cli"

// configModeEntryAllowed reports whether THIS CLI session owns a
// config-mode entry it acquired itself (via the gated `configure` verb)
// or no RBAC is in force (unset class, legacy no-RBAC mode).
// #14986: the store's config mode is GLOBAL — any gRPC/REST/daemon holder
// flips it. Routing on that flag alone let a read-only console user ride
// another holder's session into full PermConfig mutation.
func (c *CLI) configModeEntryAllowed() bool {
	return c.configOwned || c.userClass == ""
}

// checkConfigModePerm enforces the coarse PermConfig price of entering
// and mutating inside config mode. dispatchConfig previously carried
// only the *-configuration regex gate, which a built-in class with no
// regexes (read-only/unauthorized/operator) passes trivially.
// Read-only affordances (show, ?, help, exit, quit) stay available so a
// view class caught in a globally-held config mode is not trapped.
func (c *CLI) checkConfigModePerm(line string) error {
	if c.userClass == "" {
		return nil
	}
	verb := ""
	if f := strings.Fields(line); len(f) > 0 {
		verb = f[0]
	}
	switch verb {
	case "show", "?", "help", "exit", "quit":
		return nil
	}
	return c.checkPermission([]string{"configure"})
}

func (c *CLI) dispatch(line string) error {
	if cmd, pipeType, pipeArg, ok := cliterm.SplitPipe(line); ok {
		return c.dispatchWithPipe(cmd, pipeType, pipeArg)
	}

	if c.store.InConfigMode() {
		// #14986: never route into config mode on the global flag
		// alone. A session that did not itself pass the gated
		// `configure` verb gets operational dispatch (whose
		// checkPermission prices `configure` at PermConfig); if some
		// other holder owns the lock it must not be mutated or
		// committed through this CLI either.
		foreign := false
		if holder, locked := c.store.ConfigHolder(); locked && holder != "" && holder != localConfigSessionID {
			foreign = true
		}
		if !c.configModeEntryAllowed() || foreign {
			if err := c.checkConfigModePerm(line); err != nil {
				return err
			}
			if foreign {
				if f := strings.Fields(line); len(f) > 0 {
					switch f[0] {
					case "show", "?", "help":
						return c.dispatchConfig(line)
					}
				}
				return fmt.Errorf("permission denied: configuration is locked by another session")
			}
			// Non-foreign, not owned: a PermConfig class may use config
			// verbs; a view class may still use config-mode `show`.
			if f := strings.Fields(line); len(f) > 0 && (f[0] == "show" || f[0] == "?" || f[0] == "help") {
				return c.dispatchConfig(line)
			}
			// Own-class PermConfig holder whose entry predates the
			// session flag (tests / direct dispatchConfig callers):
			// fall through to dispatchConfig below.
			if err := c.checkPermission([]string{"configure"}); err == nil {
				return c.dispatchConfig(line)
			}
			return c.dispatchOperational(line)
		}
		return c.dispatchConfig(line)
	}

	if strings.HasPrefix(strings.TrimSpace(line), "show ") {
		return c.dispatchWithPager(line)
	}

	return c.dispatchOperational(line)
}

// dispatchWithPipe runs a command and applies a Junos-style output filter
// (| match/except/find/count/last/no-more) to its output. The command writes to
// a pipe that a concurrent filter goroutine consumes line-by-line via the #4709
// lineSource, so a huge "show ... | match ..." streams with bounded memory
// instead of being buffered whole with io.ReadAll first (#4731). At most one
// line (match/except/find/no-more), a running tally (count), or an n-line ring
// (last) is ever held, regardless of total output.
func (c *CLI) dispatchWithPipe(cmd, pipeType, pipeArg string) error {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	os.Stdout = w

	// The filter runs concurrently with the command: it reads the command's
	// output from r as it is produced and writes the filtered result straight
	// to the real stdout, so output is consumed lazily instead of materialized
	// up front. Every filter reads to EOF (which arrives when w is closed), so
	// no early-return drain is needed to unblock the writer.
	done := make(chan struct{})
	go func() {
		filterStream(r, origStdout, pipeType, pipeArg)
		r.Close()
		close(done)
	}()

	// Restore stdout and reap the reader in ONE deferred block (#7171) so no
	// exit path can leave the daemon's stdout pointing at the pipe. The
	// failure this was filed for -- a panic between the swap and the restore
	// -- is NOT reachable today: nothing on this path recovers, so a panic
	// takes the process down and a leaked swap cannot be observed. The class
	// that IS reachable is an early return: this function is short enough
	// that adding an error check between the swap and the restore is a
	// natural edit, and such a return would have left every later write going
	// into a pipe nobody drains AND leaked the reader goroutine blocked on
	// read. Closing w must precede <-done or the reader never sees EOF and
	// this deadlocks.
	defer func() {
		w.Close()
		os.Stdout = origStdout
		<-done
	}()

	// #7172: the command the operator ran includes its pipe, and SplitPipe has
	// already removed it. Hand it to the gate for the duration of this single
	// dispatch and clear it after, so a later un-piped command on the same CLI
	// cannot inherit a stale suffix.
	//
	// #14714: SplitPipe splits at the LAST " | ", so this frame holds the
	// rightmost stage and dispatch(cmd) recurses here for each earlier
	// stage. Accumulate rather than overwrite: prepend this stage to any
	// suffix an outer frame already installed, so the innermost frame's
	// gate sees the full chain in original order
	// (cmd | first | ... | last). Overwriting hid every stage after the
	// leftmost from allow/deny-commands — prepending a permitted
	// `| no-more` defeated a rule on the denied stage that followed it,
	// while all filter goroutines still executed.
	prevSuffix := c.pendingPipeSuffix
	stage := strings.TrimSpace(pipeType + " " + pipeArg)
	if prevSuffix != "" {
		c.pendingPipeSuffix = stage + " | " + prevSuffix
	} else {
		c.pendingPipeSuffix = stage
	}
	defer func() { c.pendingPipeSuffix = prevSuffix }()

	return c.dispatch(cmd)
}

// filterStream applies a Junos-style output filter to src, writing to out as
// each line is read.
//
// #7210: the implementation now lives in pkg/cliterm and is SHARED with the
// remote CLI client (cmd/cli). It used to live here, and the remote surface
// carried its own copy — which drifted, producing the #4968 case-folding
// divergence where `| match Foo` matched `foo` on remote but not local. A
// divergence between the two surfaces is always a bug, never a legitimate
// difference, so there is now one implementation rather than an agreement to
// maintain between two.
//
// This wrapper is kept deliberately: it preserves this package's call sites and
// keeps the #4731 / #5037 / #5069 regression tests exercising the real code path
// rather than being decommissioned by the move.
func filterStream(src io.Reader, out io.Writer, pipeType, pipeArg string) {
	cliterm.FilterStream(src, out, pipeType, pipeArg)
}

// maxTailLines is an ALIAS for the shared cap, not a second copy of the number.
// Pinning the literal again here would let the two drift silently, which is the
// failure this consolidation exists to remove.
const maxTailLines = cliterm.MaxTailLines

// parseLastCount delegates to the shared parser (see filterStream).
func parseLastCount(arg string) int {
	return cliterm.ParseLastCount(arg)
}

// dispatchWithPager runs a "show" command and pages its output. The command
// writes to a pipe that a concurrent pager goroutine consumes incrementally, so
// a huge table (a full BGP route table, millions of flow sessions) is streamed
// to the terminal a screenful at a time rather than being buffered whole in
// memory first (#4709). At most one screen of lines (plus one lookahead line
// and the OS pipe buffer) is ever held at once, regardless of total output.
// stdoutIsTerminal reports whether the process-global os.Stdout is a real
// terminal (#4886 B). It probes with TCGETS, NOT os.ModeCharDevice — /dev/null
// is a CharDevice too (CLAUDE.md TTY-detection rule). A pipe (the `| match`
// filter's os.Stdout redirect), a file redirect, or a non-interactive run all
// read as non-terminal, so the pager auto-disables and cannot nest / hang.
func stdoutIsTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS)
	return err == nil
}

func (c *CLI) dispatchWithPager(line string) error {
	// #4886 B: only page when stdout is a real terminal. A non-TTY stdout means
	// output is redirected — most importantly into the `| match/except/…` filter
	// pipe: dispatchWithPipe redirects os.Stdout to the pipe, then calls dispatch,
	// which routes a bare `show` back HERE. Engaging the pager then wrote
	// `--More--` into the hidden outer pipe while blocking on os.Stdin, so
	// `show … | match X` HUNG with no visible prompt; it also mis-paged
	// scripted / file-redirected shows. Standard pager auto-disable (like less):
	// when stdout is not a TTY, stream straight through with no pager.
	if !stdoutIsTerminal() {
		return c.dispatchOperational(line)
	}
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return c.dispatchOperational(line)
	}
	os.Stdout = w

	termHeight := 24
	if ws, wErr := unix.IoctlGetWinsize(int(origStdout.Fd()), unix.TIOCGWINSZ); wErr == nil && ws.Row > 0 {
		termHeight = int(ws.Row)
	}
	pageSize := termHeight - 1

	// The pager runs concurrently with the command: it reads the command's
	// output from r as it is produced and pauses at each "--More--". While it
	// waits for a keypress the pipe fills and the command blocks on write, so
	// output is produced lazily on demand instead of materialized up front.
	done := make(chan struct{})
	go func() {
		pageStream(r, origStdout, os.Stdin, pageSize)
		r.Close()
		close(done)
	}()

	// Restore stdout and reap the reader in ONE deferred block (#7171) so no
	// exit path can leave the daemon's stdout pointing at the pipe. The
	// failure this was filed for -- a panic between the swap and the restore
	// -- is NOT reachable today: nothing on this path recovers, so a panic
	// takes the process down and a leaked swap cannot be observed. The class
	// that IS reachable is an early return: this function is short enough
	// that adding an error check between the swap and the restore is a
	// natural edit, and such a return would have left every later write going
	// into a pipe nobody drains AND leaked the reader goroutine blocked on
	// read. Closing w must precede <-done or the reader never sees EOF and
	// this deadlocks.
	defer func() {
		w.Close()
		os.Stdout = origStdout
		<-done
	}()

	return c.dispatchOperational(line)
}

// pageStream reads newline-delimited output from src and writes it to out one
// screenful (pageSize lines) at a time, reading a single keypress from keys at
// each "--More--" prompt (space = next page, Enter = one more line, q = quit).
// It never buffers more than a single page plus one lookahead line, so the
// caller's total output can be arbitrarily large without a proportional
// allocation. On quit it drains the remaining input so a producer writing into
// a pipe never blocks.
func pageStream(src io.Reader, out io.Writer, keys io.Reader, pageSize int) {
	if pageSize < 1 {
		pageSize = 1
	}
	ls := cliterm.NewLineSource(src)

	for ls.HasMore() {
		printed := 0
		for printed < pageSize {
			l, ok := ls.Next()
			if !ok {
				break
			}
			fmt.Fprintln(out, l)
			printed++
		}

		if !ls.HasMore() {
			break
		}

		fmt.Fprint(out, "\033[7m--More--\033[0m")
		buf := make([]byte, 1)
		keys.Read(buf)
		fmt.Fprint(out, "\r        \r")

		switch buf[0] {
		case 'q', 'Q':
			// Discard the rest so a blocked pipe writer can finish.
			io.Copy(io.Discard, src)
			return
		case '\n', '\r':
			if l, ok := ls.Next(); ok {
				fmt.Fprintln(out, l)
			}
			continue
		default:
		}
	}
}

// lineSource yields newline-delimited lines from an io.Reader with one line of
// lookahead. It mirrors the semantics of strings.Split(output, "\n") with a
// trailing empty element dropped: a final line terminated by "\n" does not
// produce a phantom empty line, while an unterminated final line is returned as
// its own line. Only "\n" is treated as the delimiter, so a trailing "\r" stays
// on the line exactly as the previous strings.Split did.
var operationalCommands = []string{
	"configure", "show", "clear", "ping", "test", "traceroute",
	"monitor", "request", "quit", "exit",
}

func (c *CLI) dispatchOperational(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	if parts[0] == "?" || parts[0] == "help" {
		c.showOperationalHelp()
		return nil
	}

	resolved, err := resolveCommand(parts[0], operationalCommands)
	if err != nil {
		return err
	}
	parts[0] = resolved

	if err := c.checkPermission(parts); err != nil {
		return err
	}

	// #7172: fine-grained allow/deny command regexes, AFTER the coarse
	// permission bits authorized the family. Here rather than in dispatch()
	// because `case "run"` below re-enters this function directly from config
	// mode, so a gate at dispatch() would leave `run request system reboot`
	// ungated for anyone who can reach config mode.
	if err := c.checkCommandRegex(line); err != nil {
		return err
	}
	// #14707: `show configuration …` also carries *-configuration
	// restrictions, which the operational gate does not evaluate. A
	// whole-tree render refuses a configuration-restricted class; an
	// explicit path is adjudicated per-path (the operational arm above
	// already charged the path/format-scoped deny-commands).
	if parts[0] == "show" && len(parts) >= 2 && parts[1] == "configuration" {
		if err := c.checkShowConfigurationRead(parts[2:]); err != nil {
			return err
		}
	}
	// #14987: `show system rollback|login|root-authentication|
	// configuration rescue` render configuration through spellings the
	// gate above charged only on their literal command. The
	// *-configuration pair and the anchored `^show configuration$`
	// alternate form apply there too (parts[1] is already resolved).
	if parts[0] == "show" && len(parts) >= 2 && parts[1] == "system" {
		if err := c.checkShowSystemConfigRead(parts[1:]); err != nil {
			return err
		}
	}

	switch parts[0] {
	case "configure":
		if c.cluster != nil && !c.cluster.IsLocalPrimary(0) {
			return fmt.Errorf("error: node is not primary for RG0, configure on the primary node")
		}
		if len(parts) >= 2 && parts[1] == "exclusive" {
			if err := c.store.EnterConfigureExclusive(localConfigSessionID); err != nil {
				return err
			}
			c.configOwned = true
			if c.rl != nil {
				c.rl.SetPrompt(c.configPrompt())
			}
			fmt.Println("Entering configuration mode (exclusive)")
			fmt.Println("[edit]")
		} else {
			if err := c.store.EnterConfigureSession(localConfigSessionID); err != nil {
				return err
			}
			c.configOwned = true
			if c.rl != nil {
				c.rl.SetPrompt(c.configPrompt())
			}
			fmt.Println("Entering configuration mode")
			fmt.Println("[edit]")
		}
		return nil
	case "show":
		return c.handleShow(parts[1:])
	case "clear":
		return c.handleClear(parts[1:])
	case "ping":
		return c.handlePing(parts[1:])
	case "traceroute":
		return c.handleTraceroute(parts[1:])
	case "monitor":
		return c.handleMonitor(parts[1:])
	case "request":
		return c.handleRequest(parts[1:])
	case "test":
		return c.handleTest(parts[1:])
	case "quit", "exit":
		return errExit
	default:
		return fmt.Errorf("unknown command: %s", parts[0])
	}
}

func (c *CLI) dispatchConfig(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	// #14986: coarse PermConfig gate. dispatch() already enforces this on
	// the routed path, but direct callers (including `run …` re-entry and
	// tests) must not reach a mutating verb on regexes alone.
	if err := c.checkConfigModePerm(line); err != nil {
		return err
	}
	// #14986: a candidate exclusively held by another session must not be
	// mutated/committed from this CLI through the empty-session bypass.
	if holder, locked := c.store.ConfigHolder(); locked && holder != "" && holder != localConfigSessionID {
		switch parts[0] {
		case "show", "?", "help":
		default:
			return fmt.Errorf("permission denied: configuration is locked by another session")
		}
	}
	sessionID := ""
	if c.configOwned {
		sessionID = localConfigSessionID
	}
	// Before the switch, so one gate covers every mutating verb rather than
	// nine copies drifting apart. The gate resolves the current edit path
	// itself: each case below prefixes `store.GetEditPath()`, so matching the
	// typed fragment would let `edit system` walk a deny on
	// `system root-authentication`.
	if err := c.checkConfigRegex(line); err != nil {
		return err
	}
	// #14981: groups/apply-groups lines are judged literally above; their
	// effective expanded paths are adjudicated here, and again at commit.
	if err := c.checkConfigRegexGroups14981(line); err != nil {
		return err
	}
	// #14707: `show` in config mode renders the candidate (whole tree or
	// the edit-path subtree). The mutation gate declines it (not a verb
	// it gates) and dispatchOperational's command gate never runs here,
	// so a deny-configuration / path-scoped deny-commands class read the
	// denied subtree. Adjudicate the read with the shared decision:
	// an explicit path (edit path + typed remainder) per-path, the bare
	// `show` as a whole-tree render.
	if parts[0] == "show" {
		if err := c.checkConfigShowRegex(parts[1:]); err != nil {
			return err
		}
	}

	switch parts[0] {
	case "edit":
		// #14716: lex the typed fragment the way the store does (comments
		// skipped, quotes unquoted) and store only the lexed path. Storing
		// raw strings.Fields tokens let a decorated cursor (`edit /*
		// interfaces */ "system"`, `edit system /*`) desynchronize the
		// authorization gate from store execution.
		frag, fragOK := config.ParseEditFragment(line)
		if !fragOK {
			return fmt.Errorf("edit: invalid path")
		}
		if len(frag) == 0 {
			fmt.Println("edit: missing path")
			return nil
		}
		newPath := append(c.store.GetEditPath(), frag...)
		c.store.SetEditPath(config.NormalizeEditPathTokens(newPath))
		if c.rl != nil {
			c.rl.SetPrompt(c.configPrompt())
		}
		fmt.Printf("[edit %s]\n", strings.Join(c.store.GetEditPath(), " "))
		return nil
	case "top", "up":
		// #15082: `top <cmd>` / `up [n] <cmd>` execute cmd at the
		// target level and restore the cursor. Bare top/up stay
		// pure navigation. Previously the trailing command was
		// silently dropped with a nil return, so e.g.
		// `top delete ... policy allow-all` left the permit
		// policy in the candidate and committed it.
		return c.dispatchTopUp15082(line)
	case "set", "delete", "deactivate", "activate":
		// #15167: derive the path from the SAME config lexer the gate
		// adjudicated (config.ParseConfigMutationLine), never from
		// strings.Fields above. Fields is unicode-aware, so a Unicode
		// space after the verb or inside the path split tokens the
		// lexer stopped before — the gate judged a prefix (or only the
		// verb) while the store executed the full path, bypassing
		// allow/deny-configuration. A line that does not lex cleanly is
		// refused here for every class; a restricted class was already
		// refused by checkConfigRegex above.
		toks, _, lexOK := config.ParseConfigMutationLine(line)
		if !lexOK || len(toks) == 0 || toks[0] != parts[0] {
			return fmt.Errorf("%s: invalid path", parts[0])
		}
		if len(toks) < 2 {
			return fmt.Errorf("%s: missing path", parts[0])
		}
		fullPath := append(config.NormalizeEditPathTokens(c.store.GetEditPath()), toks[1:]...)
		// #15237 A53-07: quote tokens that would not re-lex as
		// themselves (a quoted value with interior whitespace) so
		// the store lexer recovers them as single tokens.
		joined := config.JoinConfigPathTokens(fullPath)
		plant := config.EventPlantClassForMutation(c.userClass)
		switch parts[0] {
		case "set":
			return c.store.SetFromInputAsPlantClass(sessionID, plant, joined)
		case "delete":
			return c.store.DeleteFromInputAsPlantClass(sessionID, plant, joined)
		case "deactivate":
			return c.store.DeactivateFromInputAsPlantClass(sessionID, plant, joined)
		default: // activate
			return c.store.ActivateFromInputAsPlantClass(sessionID, plant, joined)
		}
	case "copy", "rename":
		return c.handleCopyRename(line)
	case "insert":
		return c.handleInsert(line)
	case "show":
		return c.handleConfigShow(parts[1:])
	case "commit":
		return c.handleCommit(parts[1:])
	case "rollback":
		n := 0
		if len(parts) >= 2 {
			// Strict integer parse: a malformed token (e.g. "foo",
			// "1x") or a negative value must NOT silently fall through
			// to rollback 0, which discards the candidate (#3447).
			v, err := strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Errorf("rollback: invalid rollback number %q", parts[1])
			}
			if v < 0 {
				return fmt.Errorf("rollback: rollback number must be >= 0, got %d", v)
			}
			n = v
		}
		// #9892: `rollback n` for n>0 replaces the candidate with an older
		// configuration whose paths cannot be adjudicated one by one — the
		// same shape as `load override`, and ungated here for the same reason
		// (`rollback` is not in configMutationVerbs, so the gate above
		// declined). `rollback 0` returns to the COMMITTED configuration,
		// every path of which was adjudicated when it was written, and stays
		// available.
		var rbCfg *config.Config
		if c.store != nil {
			rbCfg = c.store.ActiveConfig()
		}
		if err := config.AuthorizeConfigRollback(rbCfg, c.userClass, n); err != nil {
			return err
		}
		if err := c.store.RollbackAsPlantClass(sessionID, config.EventPlantClassForMutation(c.userClass), n); err != nil {
			return err
		}
		fmt.Println("configuration rolled back")
		return nil
	case "load":
		return c.handleLoad(parts[1:])
	case "run":
		if len(parts) < 2 {
			return fmt.Errorf("run: missing command")
		}
		return c.dispatchOperational(strings.Join(parts[1:], " "))
	case "annotate":
		// #14717: parse with the ONE canonical lexer split the gate uses
		// (config.ParseAnnotateCommand -> splitAnnotateTokens): the comment
		// is the LAST token and only when authored quoted, so a quoted path
		// element stays in the path. Before this the arm re-joined
		// strings.Fields output (quoting already destroyed) and split at the
		// FIRST '"', so `annotate system "interfaces" "pwned"` was gated as
		// `system interfaces` but executed on `system` — a denied stanza
		// annotated despite deny-configuration. Every sibling mutation arm
		// and the gRPC arm pass EventPlantClassForMutation(c.userClass);
		// this arm dropped it via store.Annotate (empty plant class).
		relPath, comment, ok := config.ParseAnnotateCommand(line)
		if !ok || len(relPath) == 0 {
			fmt.Println("usage: annotate <path> \"comment\"")
			return nil
		}
		pathParts := append(config.NormalizeEditPathTokens(c.store.GetEditPath()), relPath...)
		if err := c.store.AnnotateAsPlantClass(sessionID, config.EventPlantClassForMutation(c.userClass), pathParts, comment); err != nil {
			return err
		}
		fmt.Println("annotation set")
		return nil
	case "exit", "quit":
		// #15237 A53-03: at a non-empty edit path, exit/quit behave
		// like `up` (one schema identity) and stay in configuration
		// mode; previously they discarded the candidate regardless
		// of depth. At the top level the dirty warning below fires
		// before the release.
		if ep := c.store.GetEditPath(); len(ep) > 0 {
			target := config.PopEditPathIdentity(config.NormalizeEditPathTokens(ep))
			c.store.SetEditPath(target)
			if c.rl != nil {
				c.rl.SetPrompt(c.configPrompt())
			}
			if len(target) > 0 {
				fmt.Printf("[edit %s]\n", strings.Join(target, " "))
			} else {
				fmt.Println("[edit]")
			}
			return nil
		}
		return c.exitConfigureTop()
	case "?", "help":
		c.showConfigHelp()
		return nil
	default:
		return fmt.Errorf("unknown command: %s (in configuration mode)", parts[0])
	}
}

// exitConfigureTop releases configuration mode from the top level
// (#15237 A53-03 helper; also called directly by tests whose CLI
// fixture carries no readline/configOwned wiring).
func (c *CLI) exitConfigureTop() error {
	if c.store.IsDirty() {
		fmt.Println("warning: uncommitted changes will be discarded")
	}
	c.store.ExitConfigure()
	c.configOwned = false
	if c.rl != nil {
		c.rl.SetPrompt(c.operationalPrompt())
	}
	fmt.Println("Exiting configuration mode")
	return nil
}

// dispatchTopUp15082 handles bare and prefixed top/up (#15082).
// The gate above has already adjudicated any inner mutation at the
// target cursor (configMutationPaths unwraps the same prefix), so
// execution here must act on exactly that command and cursor.
func (c *CLI) dispatchTopUp15082(line string) error {
	saved := c.store.GetEditPath()
	target, inner, ok := config.ParseTopUpPrefix15082(saved, line)
	if !ok {
		return fmt.Errorf("%s: invalid up count or malformed prefix", strings.Fields(line)[0])
	}
	if len(inner) == 0 {
		c.store.SetEditPath(target)
		if c.rl != nil {
			c.rl.SetPrompt(c.configPrompt())
		}
		if len(target) > 0 {
			fmt.Printf("[edit %s]\n", strings.Join(target, " "))
		} else {
			fmt.Println("[edit]")
		}
		return nil
	}
	if inner[0] == "top" || inner[0] == "up" || inner[0] == "edit" {
		return fmt.Errorf("%s: %s cannot follow a top/up prefix", strings.Fields(line)[0], inner[0])
	}
	c.store.SetEditPath(target)
	err := c.dispatchConfig(strings.Join(inner, " "))
	c.store.SetEditPath(saved)
	if c.rl != nil {
		c.rl.SetPrompt(c.configPrompt())
	}
	return err
}
