// Package cliterm holds the terminal-input primitives shared by the local
// console CLI (pkg/cli) and the remote CLI client (cmd/cli).
//
// It exists because those two surfaces had SEPARATE copies of the
// `load ... terminal` read loop and the copies diverged: #4883-D fixed the
// abort semantics on the remote CLI and the console kept the original
// break-on-any-error loop for two more years, silently applying
// Ctrl-C-truncated configurations (#6548). A divergence between the two is
// ALWAYS a bug — both drive the same readline instance and owe the operator
// the same answer — so the loop lives here once rather than being duplicated
// and held in step by a test.
//
// The package is deliberately tiny and dependency-light (readline plus
// the standard library, and pkg/config for the secret-leaf SSOT the
// history filter resolves through, #16794) so the remote CLI binary can
// import it without pulling in the whole interactive console.
package cliterm

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/chzyer/readline"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// StripSurroundingQuotes removes one layer of matching leading/trailing
// single or double quotes. Mismatched and unterminated quotes are preserved.
func StripSurroundingQuotes(s string) string {
	if len(s) >= 2 {
		q := s[0]
		if (q == '"' || q == '\'') && s[len(s)-1] == q {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// EscapeAnnotateComment encodes a comment for the quoted Set input accepted by
// Server.Set. Backslashes are escaped first so embedded quotes and literal
// backslashes survive the lexer round-trip.
func EscapeAnnotateComment(comment string) string {
	comment = strings.ReplaceAll(comment, `\`, `\\`)
	return strings.ReplaceAll(comment, `"`, `\"`)
}

// unescapeAnnotateComment reverses EscapeAnnotateComment while preserving
// unrelated backslash sequences verbatim.
func unescapeAnnotateComment(comment string) string {
	var b strings.Builder
	b.Grow(len(comment))
	for i := 0; i < len(comment); i++ {
		if comment[i] == '\\' && i+1 < len(comment) &&
			(comment[i+1] == '\\' || comment[i+1] == '"') {
			i++
		}
		b.WriteByte(comment[i])
	}
	return b.String()
}

// AnnotateCommentFromLine splits an `annotate <path> "comment"` line into
// path text and comment, peeling one matching quote layer and decoding escaped
// quotes/backslashes. ok is false when the line has no double-quoted comment.
func AnnotateCommentFromLine(line string) (pathText, comment string, ok bool) {
	quoteIdx := strings.Index(line, `"`)
	if quoteIdx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:quoteIdx]),
		unescapeAnnotateComment(StripSurroundingQuotes(line[quoteIdx:])), true
}

// SecureReadlineHistory creates a history file or tightens its permissions
// before readline opens it. Readline requests mode 0666 for new files, so
// relying on the process umask can leave command history readable by others.
func SecureReadlineHistory(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open history file: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("set history file permissions: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close history file: %w", err)
	}
	return nil
}

// ConfigureReadlineHistory wires cliterm's filtered on-disk history (#15284).
//
// chzyer/readline v1.5.1 has no History interface and no save-filter hook:
// Config only offers HistoryFile (a path readline itself appends every
// submitted line to from opHistory.New/Update) and DisableAutoSaveHistory.
// DisableAutoSaveHistory is NOT a persistence-only switch: operation.go's
// CharEnter arm skips history.New(data) entirely when it is set, and New() is
// the only path that commits the submitted line into the in-memory list
// (dedup, empty handling, Push of the next editing slot). The old
// DisableReadlineHistoryAutoSave helper therefore broke recall: after
// submitting a new command, Up recalled the last SEEDED entry rather than the
// command just run; a duplicate submit then recalled an empty editing slot,
// and Ctrl-D on that empty line surfaced as EOF/exit. No new command ever
// persisted either.
//
// The fix keeps readline's in-memory commit fully enabled
// (DisableAutoSaveHistory=false) but gives it NO file: HistoryFile is cleared
// so Update's `if o.fd != nil` write is a no-op and historyUpdatePath is never
// called — history.New() still does its dedup / empty / Push bookkeeping, but
// nothing reaches disk via readline's own autosave. HistoryLimit is left to
// the caller (0 selects readline's 500 default); it MUST stay well above 1:
// Compact() trims the in-memory list to the limit, and a limit of 1 keeps
// only the current editing slot, so Up would recall that empty slot —
// the same symptom as the original bug, by a second mechanism (verified
// empirically: limit=1 gives submit->Up == "", default limit gives the
// submitted line).
//
// Persistence is then explicit and filtered: callers must pass every accepted
// (non-empty, post-trim) line to RecordHistoryLine (typically via a thin
// wrapper around rl.Readline), which appends non-sensitive lines to path
// (the file SecureReadlineHistory has already tightened to 0600) and never
// writes credential-bearing lines (see IsSensitiveHistoryLine). Sensitive
// lines DO stay in readline's in-memory history for the session — recalling a
// command you just ran is not a disclosure — but they never reach the file
// that outlives it (#10743's actual intent; the file is also still wiped by
// zeroize, pkg/grpcapi).
//
// Invariants for callers (both pkg/cli and cmd/cli):
//   - Call SecureReadlineHistory(path) before ConfigureReadlineHistory so a
//     pre-existing file is 0600; the seed read here happens after that.
//   - Seed BEFORE NewEx via ReadHistorySeed: readline loads its file itself
//     only from HistoryFile, which is deliberately empty here, so the caller
//     must replay the persisted (already filtered) lines with rl.SaveHistory
//     after NewEx. SaveHistory goes through history.New, so seeding restores
//     dedup/current bookkeeping exactly as a file load would.
//   - Record every submitted line with RecordHistoryLine — including
//     sensitive ones (it filters internally), so the filter lives in one
//     place and cannot be skipped by a caller that forgets to check.
func ConfigureReadlineHistory(cfg *readline.Config) *readline.Config {
	cfg.HistoryFile = ""
	cfg.DisableAutoSaveHistory = false
	return cfg
}

// ReadHistorySeed returns the persisted history lines from path in file order
// (oldest first), skipping blank lines exactly as readline's own loader does.
// A missing file is an empty seed, not an error: first-run has no history.
// The seed filter replays config-mode navigation and retains all cursor
// interpretations made possible by an unrecorded EOF before re-entry.
func ReadHistorySeed(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read history seed: %w", err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	// Defense in depth: files written before cursor-aware history filtering
	// (or hand-edited) may contain credentials. Track every cursor state
	// consistent with history, judge each line under all of them, then
	// advance navigation even when the line itself is filtered.
	states := make([]historySeedCursor, 1, 2)
	scratch := make([]historySeedCursor, 0, 2)
	filtered := lines[:0]
	for _, line := range lines {
		configureReentry := isHistorySeedConfigureReentry(line)
		sensitive := false
		for _, state := range states {
			cursor := state.editPath
			if !state.configMode {
				cursor = nil
			}
			if IsSensitiveHistoryLineAt(cursor, line) {
				sensitive = true
				break
			}
		}
		if !sensitive {
			filtered = append(filtered, line)
		}

		next := scratch[:0]
		for _, state := range states {
			path, mode := advanceHistorySeedCursor(state.editPath, state.configMode, line)
			next = appendHistorySeedCursor(next, historySeedCursor{editPath: path, configMode: mode})
			// History cannot distinguish a rejected in-config configure
			// from a real operational re-entry after an unrecorded EOF.
			// Retain both possible cursor interpretations.
			if state.configMode && configureReentry {
				next = appendHistorySeedCursor(next, historySeedCursor{configMode: true})
			}
		}
		states, scratch = next, states[:0]
	}
	return filtered, nil
}

type historySeedCursor struct {
	editPath   []string
	configMode bool
}

func appendHistorySeedCursor(states []historySeedCursor, candidate historySeedCursor) []historySeedCursor {
	for _, state := range states {
		if state.configMode == candidate.configMode && slices.Equal(state.editPath, candidate.editPath) {
			return states
		}
	}
	return append(states, candidate)
}

func isHistorySeedConfigureReentry(line string) bool {
	for {
		command, _, _, ok := SplitPipe(line)
		if !ok {
			break
		}
		line = command
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	verb, ok := resolveHistoryOperationalVerb(fields[0])
	return ok && verb == "configure"
}

// advanceHistorySeedCursor mirrors the local and remote CLI's navigation
// transitions for history replay. History starts in operational mode, and
// the edit cursor changes only for commands that dispatch can execute as
// navigation; prefixed top/up commands restore the prior cursor after their
// inner command.
func advanceHistorySeedCursor(editPath []string, configMode bool, line string) ([]string, bool) {
	// Dispatch recursively strips each supported, unquoted output-pipe stage
	// before handling its command. Use the same splitter until no stage remains;
	// quoted pipes stay in the command data.
	for {
		command, _, _, ok := SplitPipe(line)
		if !ok {
			break
		}
		line = command
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return editPath, configMode
	}
	if !configMode {
		// Operational dispatch resolves verbs by unique prefix. Mirror
		// that resolver for configure so accepted spellings such as
		// "conf" and "config" establish the context for later lines.
		if verb, ok := resolveHistoryOperationalVerb(fields[0]); ok && verb == "configure" {
			return nil, true
		}
		return editPath, configMode
	}
	switch fields[0] {
	// dispatchConfig accepts only exact config-mode verbs, and configure
	// is not one of them. Preserve the rejected in-config interpretation
	// here; ReadHistorySeed also tracks the possible root re-entry after an
	// unrecorded EOF and filters a line if either cursor flags it sensitive.
	case "edit":
		fragment, ok := config.ParseEditFragment(line)
		if ok && len(fragment) > 0 {
			path := append(config.NormalizeEditPathTokens(editPath), fragment...)
			return config.NormalizeEditPathTokens(path), true
		}
	case "top", "up":
		target, inner, innerLine, ok := config.ParseTopUpPrefix15082(config.NormalizeEditPathTokens(editPath), line)
		if ok {
			if len(inner) == 0 {
				return target, true
			}
			// dispatchConfig switches on exact verb tokens: only an
			// unquoted exit/quit is navigation here. A top-level exit
			// releases config mode; at a non-root target exit/quit
			// pops that temporary target once, then dispatchTopUp
			// restores the original cursor while remaining in config
			// mode.
			innerFields := strings.Fields(innerLine)
			if len(innerFields) > 0 && (innerFields[0] == "exit" || innerFields[0] == "quit") {
				if len(target) == 0 {
					return nil, false
				}
				return editPath, true
			}
		}
	case "exit", "quit":
		if len(editPath) > 0 {
			return config.PopEditPathIdentity(config.NormalizeEditPathTokens(editPath)), true
		}
		return nil, false
	}
	return editPath, configMode
}

// resolveHistoryOperationalVerb uses the same candidate set and unique
// prefix rule as pkg/cli.dispatchOperational. Config-mode dispatch switches
// on exact tokens instead, so its edit/top/up/exit/quit verbs intentionally
// remain exact here too.

var historyOperationalCommands = [...]string{
	"configure", "show", "clear", "ping", "test", "traceroute",
	"monitor", "request", "quit", "exit",
}

func resolveHistoryOperationalVerb(input string) (string, bool) {
	if input == "" {
		return "", false
	}
	match := ""
	for _, command := range historyOperationalCommands {
		if command == input {
			return command, true
		}
		if strings.HasPrefix(command, input) {
			if match != "" {
				return "", false
			}
			match = command
		}
	}
	return match, match != ""
}

// SeedHistory replays persisted history lines into a live readline instance
// via SaveHistory (history.New), restoring in-memory recall + dedup state.
// An error is returned so callers can surface a broken history write rather
// than silently losing recall; with HistoryFile cleared, SaveHistory cannot
// fail on file IO (there is no fd), so this is effectively infallible.
func SeedHistory(rl *readline.Instance, lines []string) error {
	for _, line := range lines {
		if err := rl.SaveHistory(line); err != nil {
			return fmt.Errorf("seed readline history: %w", err)
		}
	}
	return nil
}

// IsSensitiveHistoryLine reports whether a submitted CLI line carries a
// credential and must never be persisted to the on-disk history file.
// It is the no-cursor form of IsSensitiveHistoryLineAt: the line alone,
// with no edit context. Callers that know the operator's edit cursor
// MUST use IsSensitiveHistoryLineAt / RecordHistoryLineAt so
// context-gated secrets resolve against their full path (#16794).
func IsSensitiveHistoryLine(line string) bool {
	return IsSensitiveHistoryLineAt(nil, line)
}

// IsSensitiveHistoryLineAt is IsSensitiveHistoryLine judged against the
// operator's resolved config path: editPath (the lexed `edit` cursor,
// e.g. store.GetEditPath() / the remote CLI's c.editPath) followed by
// the line's own lexed tokens.
//
// #16794: the previous predicate was a hand-copied token list applied
// to the flat line. It missed plain-text-password(-value) entirely and
// every edit-context spelling of the context-gated secrets: after
// `edit snmp`, `set community <s>` has no `snmp` token on the line;
// after `edit ... authentication md5 1`, `set key <s>` has no
// `authentication md5` window; after `edit ... authentication`,
// `set md5 1 key <s>` likewise. Those lines persisted cleartext
// credentials to ~/.xpf_history / ~/.xpf_cli_history — the #10743
// contract broken by the denylist that replaced the blanket ban.
//
// Resolution is now the config SSOT, not a copy: the resolved path is
// judged by config.IsSecretValueInPath16794, the union of
// secretIndices (ast_redact.go) and secretLeafKeywords (secret.go) —
// the same resolution that masks these values on every display
// surface, so the history filter cannot drift from it (pinned by
// TestHistoryPredicatePinnedToSecretSSOT16794). Lexing uses the
// store's lexer (config.ParseConfigMutationLine): quotes are consumed,
// so a quoted keyword or value is judged as the token the executor
// will act on.
//
// Verb handling: `set`/`edit` lines are judged on editPath + path
// tokens (for `edit`, the resolved NEW cursor — entering a secret
// stanza is navigation, but a value token after a secret keyword on
// that line, e.g. `edit snmp community <s>`, is a credential);
// `top`/`up <cmd>` prefixes are first resolved to their target cursor
// (config.ParseTopUpPrefix15082) so the inner command is judged where
// it will run; every other line (operational commands, bare
// navigation, show/…) is judged on its own tokens with no cursor,
// because it does not act relative to the cursor.
//
// Fail-closed arms beyond the SSOT, deliberate for a history file
// (over-suppress costs one history entry; under-suppress persists a
// credential; in-memory recall works either way):
//
//   - A config-mode set/edit/top/up line that does not lex cleanly is
//     sensitive: the unlexed tail may carry a credential the lexer
//     never produced (the #16726/#15167 doctrine).
//   - Bare `password`/`secret` tokens suppress wherever they appear,
//     as before (#15284): on a flat operational line there is no
//     ancestor path to gate on. The resolved config path needs no
//     such arm — the SSOT gates those keywords by context there —
//     but the flat arm also covers the resolved path, so it is kept
//     for both.
func IsSensitiveHistoryLineAt(editPath []string, line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	// Flat fail-closed arm (#15284, kept): bare password/secret tokens
	// anywhere on the raw line. Quote-stripped Fields, as before, so a
	// quoted keyword still matches even on a line the config lexer
	// would refuse (e.g. an operational command with shell-ish text).
	for _, raw := range strings.Fields(line) {
		switch strings.Trim(raw, `"'`) {
		case "password", "secret":
			return true
		}
	}
	tokens, _, lexOK := config.ParseConfigMutationLine(line)
	if len(tokens) == 0 {
		// Nothing lexed: an operational line the flat arm already
		// judged, or an unlexable line whose first token never
		// surfaced. A set/edit/top/up opener hiding in the unlexed
		// text cannot be ruled out when lexing failed — fail closed
		// only for those openers, spotted on the raw Fields view.
		if !lexOK {
			if f := strings.Fields(line); len(f) > 0 {
				switch strings.Trim(f[0], `"'`) {
				case "set", "edit", "top", "up":
					return true
				}
			}
		}
		return false
	}
	return sensitiveTokensAt(editPath, tokens, lexOK, line)
}

// sensitiveTokensAt judges lexed tokens against editPath; lexOK is the
// config lexer's clean-end-to-end flag for the line they came from, and
// line is that raw line (top/up resolution re-lexes its prefix the way
// the executor does). Recursive top/up calls pass lexOK=true with the
// inner tokens already lexed, so no re-joined string is ever re-judged
// with different tokenization than the executor's.
func sensitiveTokensAt(editPath []string, tokens []string, lexOK bool, line string) bool {
	switch tokens[0] {
	case "top", "up":
		target, inner, _, ok := config.ParseTopUpPrefix15082(config.NormalizeEditPathTokens(editPath), line)
		if !ok {
			// Malformed prefix with a trailing command: the inner
			// command's target cannot be resolved — fail closed.
			// Bare malformed navigation carries no value token.
			return len(tokens) > 1
		}
		if len(inner) == 0 {
			return false // bare navigation: no path, no value
		}
		if !lexOK {
			return true
		}
		return sensitiveTokensAt(target, inner, true, strings.Join(inner, " "))
	case "set", "edit":
		if !lexOK {
			return true
		}
		resolved := append(append([]string{}, config.NormalizeEditPathTokens(editPath)...), tokens[1:]...)
		return config.IsSecretValueInPath16794(resolved)
	default:
		// Operational / other lines do not act relative to the cursor;
		// judge the line's own tokens through the same SSOT union
		// (which marks values after distinctive and gated keywords
		// wherever their context appears on the line itself), plus
		// the flat bare password/secret arm in the caller.
		return config.IsSecretValueInPath16794(tokens)
	}
}

// maxPersistedHistoryLines bounds the on-disk history file. readline's
// native loader rewrote the file when the seeded count exceeded
// HistoryLimit; with readline no longer owning the file, RecordHistoryLine
// must bound it or a long-lived CLI grows the file without limit. When an
// append would exceed the bound, the file is rewritten with only the newest
// maxPersistedHistoryLines lines (same value both CLIs pass as HistoryLimit).
const maxPersistedHistoryLines = 10000

// RecordHistoryLine persists one submitted CLI line to the history file at
// path, unless the line is empty or credential-bearing (IsSensitiveHistoryLine).
// It is the no-cursor form of RecordHistoryLineAt; callers that know the
// operator's edit cursor MUST use RecordHistoryLineAt (#16794).
func RecordHistoryLine(path, line string) error {
	return RecordHistoryLineAt(nil, path, line)
}

// RecordHistoryLineAt is RecordHistoryLine with the operator's edit
// cursor: the line is filtered by IsSensitiveHistoryLineAt(editPath, …)
// so a context-gated secret typed relative to an `edit` stanza is
// suppressed exactly as its flat spelling is. It appends rather than
// rewriting (except for the bound trim below): readline (with
// HistoryFile cleared) never rewrites or truncates the file, so this
// append is the only writer and file order is submission order. The
// caller must have tightened the file with SecureReadlineHistory first;
// the append opens with 0600 so a file created here
// (SecureReadlineHistory normally pre-creates it) is never laxer.
// Duplicate and consecutive-duplicate lines are appended as submitted —
// readline's in-memory dedup governs recall, and suppressing a duplicate
// on disk would make the persisted order diverge from what the operator
// ran.
func RecordHistoryLineAt(editPath []string, path, line string) error {
	line = strings.TrimSpace(line)
	if line == "" || path == "" {
		return nil
	}
	if IsSensitiveHistoryLineAt(editPath, line) {
		return nil
	}
	// Read-then-append is not atomic against a second CLI process sharing
	// the same $HOME history file; the worst case is a lost or duplicated
	// line, or the bound-trim racing a peer append. That matches readline's
	// own multi-process history behaviour (it also appends unsynchronised)
	// and history is advisory operator state, never a security boundary —
	// the sensitive-line filter above is re-checked on the line actually
	// submitted here, in-process, so a race can never write a credential.
	seed, err := ReadHistorySeed(path)
	if err != nil {
		return err
	}
	seed = append(seed, line)
	if len(seed) > maxPersistedHistoryLines {
		seed = seed[len(seed)-maxPersistedHistoryLines:]
		var b strings.Builder
		for _, l := range seed {
			b.WriteString(l + "\n")
		}
		// Rewrite atomically so a crash mid-write cannot leave a
		// half-written history (readline's own rewriteLocked used the
		// same pattern); WriteFileAtomic stages a 0600 temp in the same
		// directory and renames it over the 0600 original, preserving
		// SecureReadlineHistory's guarantee. History is advisory
		// operator state, not DurableState, so the non-durable atomic
		// class is the right one (#16723 fsatomic classification).
		if err := fsatomic.WriteFileAtomic(path, []byte(b.String()), 0o600); err != nil {
			return fmt.Errorf("rewrite history file: %w", err)
		}
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open history file: %w", err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("append history line: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close history file: %w", err)
	}
	return nil
}

// ReadConfig collects a pasted configuration from readLine until the input is
// COMMITTED by Ctrl-D (io.EOF). A readline.ErrInterrupt (Ctrl-C) or any other
// read error is an ABORT: the partial input is discarded and a non-nil error
// is returned, so the caller does NOT apply a truncated subset of the config
// as if it were complete.
//
// The distinction is the whole point. Both CLIs originally took the same
// `break` for EOF, ErrInterrupt, and every read error, then joined whatever
// lines had been collected, Loaded them, and printed "load ... complete". An
// operator who aborts a paste is told it succeeded, and a truncated
// `security policies` stanza is a WIDENED one — the deny terms that would have
// followed never arrive. Only EOF commits.
//
// It returns the empty string on abort rather than the partial content: a
// caller cannot accidentally use a discarded paste, and the empty-input check
// callers already perform is not the thing standing between a Ctrl-C and a
// truncated commit.
func ReadConfig(readLine func() (string, error)) (string, error) {
	var lines []string
	for {
		line, err := readLine()
		if err != nil {
			if err == io.EOF {
				return strings.Join(lines, "\n"), nil
			}
			if err == readline.ErrInterrupt {
				return "", fmt.Errorf("load terminal: aborted (partial input discarded)")
			}
			return "", fmt.Errorf("load terminal: read error: %v", err)
		}
		lines = append(lines, line)
	}
}
