// cli is the remote CLI client for xpfd.
//
// It connects to the xpfd gRPC API and provides the same Junos-style
// interactive CLI as the embedded console.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chzyer/readline"
	"github.com/psaab/xpf/pkg/cliterm"
	"github.com/psaab/xpf/pkg/cmdtree"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

var errExit = fmt.Errorf("exit")

var pipeFilterDescs = map[string]string{
	"count":   "Count occurrences",
	"display": "Show additional kinds of information",
	"except":  "Show only text that does not match a pattern",
	"find":    "Search for first occurrence of pattern",
	"grep":    "Show only text that matches a pattern",
	"last":    "Display end of output only",
	"match":   "Show only text that matches a pattern",
	"no-more": "Don't paginate output",
}

type ctl struct {
	client   pb.BpfrxServiceClient
	rl       *readline.Instance
	hostname string
	username string
	// configMode is read by the SIGINT goroutine (main.go) concurrently
	// with the main loop's mode transitions, so it MUST be accessed
	// atomically. A racy read let a Ctrl-C that landed during a
	// configure/exit/EOF transition observe stale state and skip the
	// explicit ExitConfigure cleanup on the way out (#5053).
	configMode    atomic.Bool
	editPath      []string
	clusterRole   string // "primary", "secondary", or "" (not clustered)
	clusterNodeID int32

	// Command cancellation: Ctrl-C during a running command cancels it.
	cmdMu     sync.Mutex
	cmdCtx    context.Context    // per-command context, cancelled by Ctrl-C
	cmdCancel context.CancelFunc // non-nil while a command is executing
}

type remoteCompleter struct {
	ctl         *ctl
	helpWritten bool // set by ? Listener to suppress duplicate help from Do()
}

// startCmd creates a cancellable context for the current command.
// Must call endCmd() when the command finishes.
func (c *ctl) startCmd() {
	c.cmdMu.Lock()
	c.cmdCtx, c.cmdCancel = context.WithCancel(context.Background())
	c.cmdMu.Unlock()
}

// endCmd clears the per-command context.
func (c *ctl) endCmd() {
	c.cmdMu.Lock()
	if c.cmdCancel != nil {
		c.cmdCancel()
	}
	c.cmdCtx = nil
	c.cmdCancel = nil
	c.cmdMu.Unlock()
}

// ctx returns the current command context, or background if none.
func (c *ctl) ctx() context.Context {
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()
	if c.cmdCtx != nil {
		return c.cmdCtx
	}
	return context.Background()
}

// cancelCmd cancels any running command. Returns true if a command was cancelled.
func (c *ctl) cancelCmd() bool {
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()
	if c.cmdCancel != nil {
		c.cmdCancel()
		return true
	}
	return false
}

func (c *ctl) dispatch(line string) error {
	// Extract pipe filter (| match, | except, | find, | count, | last, | no-more).
	// Skip | display set and | compare.
	if cmd, pipeType, pipeArg, ok := cliterm.SplitPipe(line); ok {
		return c.dispatchWithPipe(cmd, pipeType, pipeArg)
	}

	if c.configMode.Load() {
		return c.dispatchConfig(line)
	}
	return c.dispatchOperational(line)
}

// extractPipe splits a line at the last "| <filter>" expression.

// dispatchWithPipe runs the command and applies the pipe filter.
//
// #7210: the filter runs CONCURRENTLY with the command, reading its output from
// r as it is produced and writing the filtered result straight to the real
// stdout. Previously this did io.ReadAll into a []byte and then
// strings.Split into a []string — materializing the entire output TWICE before
// the filter ran, so `show log messages | match error` against a large syslog
// buffer, or `show route | count` on a big table, could OOM the operator's own
// cli process on a memory-constrained jump host. (Client-side only: the daemon
// streams normally and was never affected.)
//
// The filter itself is pkg/cliterm.FilterStream, the SAME implementation the
// in-process CLI uses. That is the other half of the fix: the remote surface
// used to carry its own copy, and it drifted (#4968). Every filter reads to EOF
// — which arrives when w is closed — so no early-return drain is needed to
// unblock the writer.
func (c *ctl) dispatchWithPipe(cmd, pipeType, pipeArg string) error {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	os.Stdout = w

	done := make(chan struct{})
	go func() {
		cliterm.FilterStream(r, origStdout, pipeType, pipeArg)
		r.Close()
		close(done)
	}()

	// Restore stdout and reap the filter in ONE deferred block (#7171) so no
	// exit path can leave the process's stdout pointing at the pipe. The
	// failure this was filed for -- a panic between the swap and the restore
	// -- is NOT reachable today: nothing on this path recovers, so a panic
	// takes the process down and a leaked swap cannot be observed. The class
	// that IS reachable is an early return: both of these functions are short
	// enough that adding an error check between the swap and the restore is a
	// natural edit, and such a return would have left every later write going
	// into a pipe nobody drains AND leaked the filter goroutine blocked on
	// read. Closing w must precede <-done or the filter never sees EOF and
	// this deadlocks.
	defer func() {
		w.Close()
		os.Stdout = origStdout
		<-done
	}()

	return c.dispatch(cmd)
}

func (c *ctl) dispatchOperational(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "configure":
		// Hard-error when the readline instance is nil (i.e. `cli -c
		// "configure"` from a non-TTY context). Entering configuration
		// mode without a follow-up interactive command is useless: -c
		// runs a single command and exits, so the configMode flag is
		// immediately discarded. Worse, the daemon-side gRPC
		// configLockInterceptor (pkg/grpcapi/server.go) is a UNARY
		// interceptor — it only fires while an RPC is in flight, never
		// on connection close. Issuing EnterConfigure here and exiting
		// would leak the daemon-side config lock until daemon restart.
		// Exclusive locks were historically worse: EnterConfigureExclusive
		// records the holder in `exclusiveHolder`, but ExitConfigureSession
		// used to release only when the session matched `configHolder`, so
		// even an explicit teardown could not recover them. #3979 fixed the
		// release path to match the effective holder; this -c leak is
		// unaffected by that fix because it stems from the interceptor never
		// firing on an idle connection close, not the holder mismatch.
		// See #1563, #3979.
		if c.rl == nil {
			return fmt.Errorf(
				"configuration mode requires an interactive terminal " +
					"(TTY); not available in -c mode")
		}
		exclusive := len(parts) >= 2 && parts[1] == "exclusive"
		_, err := c.client.EnterConfigure(c.ctx(), &pb.EnterConfigureRequest{
			Exclusive: exclusive,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		c.configMode.Store(true)
		c.rl.SetPrompt(c.configPrompt())
		if exclusive {
			fmt.Println("Entering configuration mode (exclusive)")
		} else {
			fmt.Println("Entering configuration mode")
		}
		fmt.Println("[edit]")
		return nil

	case "show":
		if len(parts) >= 2 && parts[1] == "version" {
			return c.showCommand("show version")
		}
		return c.handleShow(parts[1:])

	case "clear":
		return c.handleClear(parts[1:])

	case "ping":
		return c.handlePing(parts[1:])

	case "traceroute":
		return c.handleTraceroute(parts[1:])

	case "request":
		return c.handleRequest(parts[1:])

	case "test":
		return c.handleTest(parts[1:])

	case "monitor":
		return c.handleMonitor(parts[1:])

	case "quit", "exit":
		return errExit

	case "?", "help":
		c.showOperationalHelp()
		return nil

	default:
		return fmt.Errorf("unknown command: %s", parts[0])
	}
}

// parseRollbackSelector converts a rollback slot/index token into the int32
// the rollback RPCs carry. strconv.Atoi returns a 64-bit int on this target,
// so a value like 4294967297 parsed clean, passed a naive lower-bound check,
// then int32() WRAPPED to a different in-range slot (4294967297 -> 1): the
// mutating path silently discarded the candidate (#4868) and the read-only
// display/compare selectors silently rendered the WRONG rollback with a
// success exit (#5052). ParseInt with a 32-bit width returns strconv.ErrRange
// for any value outside int32 range instead of wrapping, so the truncation can
// never reach the wire.
//
// min is the smallest accepted value: 0 for the mutating `rollback` (0 =
// revert to active / discard candidate), 1 for the read-only display/compare
// selectors that require a positive history slot. usage is the caller's syntax
// hint, echoed on every failure so the operator sees the offending command.
func parseRollbackSelector(token, usage string, min int32) (int32, error) {
	v, err := strconv.ParseInt(token, 10, 32)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, fmt.Errorf("rollback number %q out of range; %s", token, usage)
		}
		return 0, fmt.Errorf("%s", usage)
	}
	if v < int64(min) {
		return 0, fmt.Errorf("%s", usage)
	}
	return int32(v), nil
}

func (c *ctl) dispatchConfig(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "edit":
		if len(parts) < 2 {
			fmt.Println("edit: missing path")
			return nil
		}
		c.editPath = append(c.editPath, parts[1:]...)
		if c.rl != nil {
			c.rl.SetPrompt(c.configPrompt())
		}
		fmt.Printf("[edit %s]\n", strings.Join(c.editPath, " "))
		return nil

	case "top":
		c.editPath = nil
		if c.rl != nil {
			c.rl.SetPrompt(c.configPrompt())
		}
		fmt.Println("[edit]")
		return nil

	case "up":
		if len(c.editPath) > 0 {
			c.editPath = c.editPath[:len(c.editPath)-1]
		}
		if c.rl != nil {
			c.rl.SetPrompt(c.configPrompt())
		}
		if len(c.editPath) > 0 {
			fmt.Printf("[edit %s]\n", strings.Join(c.editPath, " "))
		} else {
			fmt.Println("[edit]")
		}
		return nil

	case "set":
		if len(parts) < 2 {
			return fmt.Errorf("set: missing path")
		}
		fullPath := append(append([]string{}, c.editPath...), parts[1:]...)
		_, err := c.client.Set(c.ctx(), &pb.SetRequest{
			Input: strings.Join(fullPath, " "),
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return nil

	case "delete":
		if len(parts) < 2 {
			return fmt.Errorf("delete: missing path")
		}
		fullPath := append(append([]string{}, c.editPath...), parts[1:]...)
		_, err := c.client.Delete(c.ctx(), &pb.DeleteRequest{
			Input: strings.Join(fullPath, " "),
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return nil

	case "deactivate", "activate":
		// #2051: activate/deactivate ride the Set RPC with the verb kept as
		// the input prefix. The gRPC Set handler prefix-routes "deactivate "/
		// "activate " to Deactivate/ActivateFromInput; sending the bare path
		// (or using the Delete RPC) would mangle it into a junk "set" path.
		if len(parts) < 2 {
			return fmt.Errorf("%s: missing path", parts[0])
		}
		fullPath := append(append([]string{}, c.editPath...), parts[1:]...)
		_, err := c.client.Set(c.ctx(), &pb.SetRequest{
			Input: parts[0] + " " + strings.Join(fullPath, " "),
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return nil

	case "annotate":
		// #13554: annotate rides Set like the other config mutations routed
		// through Server.Set, with the verb retained for authorization.
		remainder := strings.TrimSpace(strings.TrimPrefix(line, parts[0]))
		pathText, comment, ok := cliterm.AnnotateCommentFromLine(remainder)
		if !ok || len(strings.Fields(pathText)) == 0 {
			fmt.Println("usage: annotate <path> \"comment\"")
			return nil
		}
		fullPath := append(append([]string{}, c.editPath...), strings.Fields(pathText)...)
		input := "annotate " + strings.Join(fullPath, " ") + " \"" + cliterm.EscapeAnnotateComment(comment) + "\""
		_, err := c.client.Set(c.ctx(), &pb.SetRequest{Input: input})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println("annotation set")
		return nil
	case "copy", "rename":
		toIdx := -1
		for i, p := range parts {
			if p == "to" {
				toIdx = i
				break
			}
		}
		if toIdx < 2 || toIdx >= len(parts)-1 {
			fmt.Printf("usage: %s <src-path> to <dst-path>\n", parts[0])
			return nil
		}
		srcParts := parts[1:toIdx]
		dstParts := parts[toIdx+1:]
		if len(c.editPath) > 0 {
			srcParts = append(append([]string{}, c.editPath...), srcParts...)
			dstParts = append(append([]string{}, c.editPath...), dstParts...)
		}
		fullInput := parts[0] + " " + strings.Join(srcParts, " ") + " to " + strings.Join(dstParts, " ")
		_, err := c.client.Set(c.ctx(), &pb.SetRequest{Input: fullInput})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return nil

	case "insert":
		kwIdx := -1
		for i, p := range parts {
			if p == "before" || p == "after" {
				kwIdx = i
				break
			}
		}
		if kwIdx < 2 || kwIdx >= len(parts)-1 {
			fmt.Println("usage: insert <element-path> before|after <ref-identifier>")
			return nil
		}
		elemParts := parts[1:kwIdx]
		kw := parts[kwIdx]
		refTokens := parts[kwIdx+1:]
		if len(c.editPath) > 0 {
			elemParts = append(append([]string{}, c.editPath...), elemParts...)
		}
		fullInput := "insert " + strings.Join(elemParts, " ") + " " + kw + " " + strings.Join(refTokens, " ")
		_, err := c.client.Set(c.ctx(), &pb.SetRequest{Input: fullInput})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		return nil

	case "show":
		return c.handleConfigShow(parts[1:])

	case "commit":
		return c.handleCommit(parts[1:])

	case "rollback":
		n := int32(0)
		if len(parts) >= 2 {
			// Strict integer parse via the shared selector parser
			// (#3447/#4868/#5052): a malformed token ("foo", "1x"), a
			// negative value, or an int32-overflowing value must NOT
			// silently fall through to rollback 0 (which discards the
			// candidate). min=0 keeps `rollback 0` valid (revert to
			// active). See parseRollbackSelector for the int32-wrap
			// rationale.
			v, err := parseRollbackSelector(parts[1], "rollback: rollback number must be a non-negative integer within int32 range", 0)
			if err != nil {
				return err
			}
			n = v
		}
		_, err := c.client.Rollback(c.ctx(), &pb.RollbackRequest{N: n})
		if err != nil {
			return fmt.Errorf("%v", err)
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

	case "exit", "quit":
		// #5812: an explicit exit/quit is a TRANSACTIONAL client state change,
		// not best-effort teardown. If the ExitConfigure release RPC fails (a
		// transport timeout/disconnect before it reaches the daemon), the
		// server-side configuration lock + candidate may still be owned by THIS
		// session — so do NOT clear local config-mode state. Clearing it would
		// drop the operator to operational mode believing they released, throwing
		// away the only immediate in-process retry path (the session still holds
		// the lock, so re-issuing `exit` IS the correct recovery). Surface the
		// error and stay in configuration mode with editPath/prompt intact. The
		// RPC is idempotent server-side, so a retry after a response-lost success
		// still returns success and transitions cleanly. Only Store(false) on
		// success (the SIGINT goroutine reads configMode concurrently, #5053).
		// The EOF / process-teardown path (main.go exitConfigureBounded) stays
		// best-effort and is deliberately left unchanged — the client is exiting
		// anyway and has no interactive recovery.
		if _, err := c.client.ExitConfigure(c.ctx(), &pb.ExitConfigureRequest{}); err != nil {
			return fmt.Errorf("failed to release configuration lock: %w; still in configuration mode, retry `exit`", err)
		}
		c.configMode.Store(false)
		c.editPath = nil
		if c.rl != nil {
			c.rl.SetPrompt(c.operationalPrompt())
		}
		fmt.Println("Exiting configuration mode")
		return nil

	case "?", "help":
		c.showConfigHelp()
		return nil

	default:
		return fmt.Errorf("unknown command: %s (in configuration mode)", parts[0])
	}
}

func (c *ctl) refreshPrompt() {
	if h, err := os.Hostname(); err == nil && h != "" {
		c.hostname = h
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if resp, err := c.client.GetStatus(ctx, &pb.GetStatusRequest{}); err == nil {
		c.clusterRole = resp.ClusterRole
		c.clusterNodeID = resp.ClusterNodeId
	}
	cancel()
	if c.rl != nil {
		if c.configMode.Load() {
			c.rl.SetPrompt(c.configPrompt())
		} else {
			c.rl.SetPrompt(c.operationalPrompt())
		}
	}
}

// --- Prompts ---

func (c *ctl) clusterPrefix() string {
	if c.clusterRole == "" {
		return ""
	}
	return fmt.Sprintf("{%s:node%d}", c.clusterRole, c.clusterNodeID)
}

func (c *ctl) operationalPrompt() string {
	return fmt.Sprintf("%s%s@%s> ", c.clusterPrefix(), c.username, c.hostname)
}

func (c *ctl) configPrompt() string {
	return fmt.Sprintf("%s%s@%s# ", c.clusterPrefix(), c.username, c.hostname)
}

// --- Help ---

func (c *ctl) showOperationalHelp() {
	cmdtree.WriteHelp(os.Stdout, cmdtree.HelpCandidates(cmdtree.OperationalTree))
}

func (c *ctl) showConfigHelp() {
	cmdtree.WriteHelp(os.Stdout, cmdtree.HelpCandidates(cmdtree.ConfigTopLevel))
}

// completionCursor derives the CompleteRequest cursor fields from a readline
// (line, pos) pair. readline reports pos as a RUNE index into the rune slice,
// but the server's Complete interprets CompleteRequest.Pos as a BYTE offset
// into CompleteRequest.Line (it does text[:req.Pos]). Send the byte length of
// the prefix so the two units agree even when the prefix holds multibyte runes.
//
// Sending the rune index made pos < len(prefixBytes) whenever a multibyte rune
// preceded the cursor, so the server re-sliced req.Line mid-rune and corrupted
// the token being completed (#4970). Because text is already the prefix up to
// the cursor, its byte length equals len(text) and the server's guard
// (int(req.Pos) < len(text)) is then false — it never re-slices. This matches
// the `?` help listener in main.go, which already sends int32(len(text)).
func completionCursor(line []rune, pos int) (string, int32) {
	text := string(line[:pos])
	return text, int32(len(text))
}

func (rc *remoteCompleter) Do(line []rune, pos int) ([][]rune, int) {
	if rc.helpWritten {
		rc.helpWritten = false
		return nil, 0
	}

	text, cursor := completionCursor(line, pos)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := rc.ctl.client.Complete(ctx, &pb.CompleteRequest{
		Line:       text,
		Pos:        cursor,
		ConfigMode: rc.ctl.configMode.Load(),
	})
	if err != nil || len(resp.Candidates) == 0 {
		return nil, 0
	}

	isPipe := strings.Contains(text, "|")
	var partial string
	if isPipe {
		idx := strings.LastIndex(text, "|")
		after := strings.TrimLeft(text[idx+1:], " ")
		trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
		if !trailingSpace && after != "" {
			partial = after
		}
	} else {
		words := strings.Fields(text)
		trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
		if !trailingSpace && len(words) > 0 {
			partial = words[len(words)-1]
		}
	}

	sort.Strings(resp.Candidates)

	if len(resp.Candidates) == 1 {
		suffix := resp.Candidates[0][len(partial):]
		return [][]rune{[]rune(suffix + " ")}, len(partial)
	}

	words := strings.Fields(text)
	candidates := make([]cmdtree.Candidate, len(resp.Candidates))
	for i, name := range resp.Candidates {
		desc := ""
		if i < len(resp.Descriptions) && resp.Descriptions[i] != "" {
			desc = resp.Descriptions[i]
		} else if isPipe {
			desc = pipeFilterDescs[name]
		} else {
			desc = remoteLookupDesc(words, name, rc.ctl.configMode.Load())
		}
		candidates[i] = cmdtree.Candidate{Name: name, Desc: desc}
	}
	cmdtree.WriteHelp(rc.ctl.rl.Stdout(), candidates)

	cp := cmdtree.CommonPrefix(resp.Candidates)
	suffix := cp[len(partial):]
	if suffix == "" {
		return nil, 0
	}
	return [][]rune{[]rune(suffix)}, len(partial)
}

// remoteLookupDesc finds the description for a candidate name by walking
// the canonical command tree in pkg/cmdtree. No manual desc map needed.
func remoteLookupDesc(words []string, name string, configMode bool) string {
	return cmdtree.LookupDesc(words, name, configMode)
}

// printRemoteTreeHelp prints self-generating help by walking the canonical
// command tree. path elements are used to navigate to the right subtree.
func printRemoteTreeHelp(header string, path ...string) {
	cmdtree.PrintTreeHelp(header, cmdtree.OperationalTree, path...)
}

// printConfigTreeHelp prints self-generating help from the config tree.
func printConfigTreeHelp(header string, path ...string) {
	cmdtree.PrintTreeHelp(header, cmdtree.ConfigTopLevel, path...)
}
