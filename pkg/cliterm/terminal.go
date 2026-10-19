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
// The package is deliberately tiny and dependency-light (readline plus the
// standard library) so the remote CLI binary can import it without pulling in
// the whole interactive console.
package cliterm

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chzyer/readline"
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
// The lines were filtered by RecordHistoryLine when written, so no sensitive
// line is ever seeded back.
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
	// Defense in depth: a history file written before the #15284 filter (or
	// hand-edited) may contain a credential line the old always-on autosave
	// persisted. Never seed those back into a live session's recall, where a
	// later Rewrite-free session would re-expose them; RecordHistoryLine will
	// also keep them off disk going forward because seeding never writes.
	filtered := lines[:0]
	for _, line := range lines {
		if IsSensitiveHistoryLine(line) {
			continue
		}
		filtered = append(filtered, line)
	}
	return filtered, nil
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
//
// The token set mirrors the secret-leaf signatures in
// pkg/config/ast_redact.go (secretIndices) — the codebase's single reviewed
// list of credential-bearing config keywords — applied to a flat command
// line instead of a flattened AST path: the distinctive keywords
// (pre-shared-key, authentication-key, authentication-password,
// privacy-password, encrypted-password, simple/password under a credential
// context, api-key, tsig-secret, api-token, aws-secret-key, private-key,
// preshared-key, community under snmp, key under `authentication md5`,
// secret under an api-auth key stanza). Two deliberate differences from
// ast_redact, both fail-closed (over-suppress, never under-suppress):
//
//   - `password` and bare `secret` are treated as sensitive wherever they
//     appear as a token. On a flat CLI line there is no ancestor path to
//     gate on, and a history file is a strictly worse place to be wrong
//     than a display redactor: suppressing a benign `show ... password ...`
//     line from disk costs one history entry; persisting a bind password
//     costs a credential. In-memory recall still works either way.
//   - `community` is sensitive only directly after `snmp` (same as
//     ast_redact): `set snmp community <string>` carries the v1/v2c shared
//     secret as the token after `community`. A routing `community`
//     (policy-options) has no `snmp` predecessor on a CLI line either.
//
// `key` stays gated on the `authentication md5 <id> key <secret>` context
// (same as ast_redact) because bare `key` is common in non-secret commands
// (`show ... key ...`, GRE tunnel keys are identifiers, not credentials, in
// Junos spelling `tunnel ... key <id>` is a numeric identifier). Tokens are
// compared after stripping surrounding quotes, so
// `pre-shared-key ascii-text "hunter2"` and quoted keywords still match.
func IsSensitiveHistoryLine(line string) bool {
	fields := strings.Fields(line)
	for i, raw := range fields {
		tok := strings.Trim(raw, `"'`)
		switch tok {
		case "pre-shared-key", "authentication-key", "additional-authentication-key",
			"authentication-password", "privacy-password", "encrypted-password",
			"simple-password", "api-key", "tsig-secret", "api-token",
			"aws-secret-key", "private-key", "preshared-key",
			"password", "secret":
			return true
		case "community":
			if i >= 1 && strings.Trim(fields[i-1], `"'`) == "snmp" {
				return true
			}
		case "key":
			// `authentication md5 <key-id> key <secret>` — mirrors ast_redact.
			if i >= 3 && strings.Trim(fields[i-2], `"'`) == "md5" &&
				strings.Trim(fields[i-3], `"'`) == "authentication" {
				return true
			}
		}
	}
	return false
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
// It appends rather than rewriting (except for the bound trim above):
// readline (with HistoryFile cleared) never rewrites or truncates the file,
// so this append is the only writer and file order is submission order. The
// caller must have tightened the file with SecureReadlineHistory first; the
// append opens with 0600 so a file created here (SecureReadlineHistory
// normally pre-creates it) is never laxer. Duplicate and consecutive-duplicate
// lines are appended as submitted — readline's in-memory dedup governs
// recall, and suppressing a duplicate on disk would make the persisted order
// diverge from what the operator ran.
func RecordHistoryLine(path, line string) error {
	line = strings.TrimSpace(line)
	if line == "" || path == "" {
		return nil
	}
	if IsSensitiveHistoryLine(line) {
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
		// Rewrite via a same-directory temp + rename so a crash mid-write
		// cannot leave a half-written history (readline's own rewriteLocked
		// used the same pattern); the temp is created 0600 and renamed over
		// the 0600 original, preserving SecureReadlineHistory's guarantee.
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
			return fmt.Errorf("rewrite history file: %w", err)
		}
		if err := os.Rename(tmp, path); err != nil {
			return fmt.Errorf("replace history file: %w", err)
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
