package cliterm

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chzyer/readline"
)

// The contract this package exists to hold, asserted directly rather than only
// through either CLI's entry point: ONLY Ctrl-D (io.EOF) commits a pasted
// configuration. Everything else discards it.
//
// Both CLIs previously owned a copy of this loop, both copies took the same
// `break` for EOF / ErrInterrupt / read error, and #4883-D fixed one of them.
// The console kept applying Ctrl-C-truncated pastes as complete until #6548.

func scripted(lines []string, end error) func() (string, error) {
	i := 0
	return func() (string, error) {
		if i < len(lines) {
			i++
			return lines[i-1], nil
		}
		return "", end
	}
}

func TestEOFCommitsTheCollectedLines(t *testing.T) {
	got, err := ReadConfig(scripted([]string{"a", "b", "c"}, io.EOF))
	if err != nil {
		t.Fatalf("EOF must commit: %v", err)
	}
	if got != "a\nb\nc" {
		t.Fatalf("content = %q, want %q", got, "a\nb\nc")
	}
}

func TestEOFWithNoLinesIsEmptyAndNotAnError(t *testing.T) {
	// An immediate Ctrl-D is an empty paste, not an abort; the caller's own
	// empty-input check reports it.
	got, err := ReadConfig(scripted(nil, io.EOF))
	if err != nil || got != "" {
		t.Fatalf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestInterruptAbortsAndDiscardsThePartialPaste(t *testing.T) {
	got, err := ReadConfig(scripted([]string{"a", "b"}, readline.ErrInterrupt))
	if err == nil {
		t.Fatal("Ctrl-C must abort, not commit the partial paste")
	}
	if got != "" {
		t.Fatalf("aborted read returned partial content %q — a caller that "+
			"ignores the error would apply it", got)
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Errorf("error %q does not say the paste was aborted", err)
	}
}

func TestOtherReadErrorsAlsoAbort(t *testing.T) {
	got, err := ReadConfig(scripted([]string{"a"}, errors.New("tty vanished")))
	if err == nil {
		t.Fatal("a read error must abort")
	}
	if got != "" {
		t.Fatalf("aborted read returned partial content %q", got)
	}
	if !strings.Contains(err.Error(), "tty vanished") {
		t.Errorf("error %q loses the underlying cause", err)
	}
}

// newHistoryReadline builds a readline instance wired exactly as both CLI
// surfaces wire it in production (ConfigureReadlineHistory + seed replay),
// driven by an in-memory pipe so tests can submit lines and recall keys
// without a PTY. The caller keeps the pipe writer to feed the session.
func newHistoryReadline(t *testing.T, historyFile string, seed []string) (*readline.Instance, *os.File) {
	t.Helper()
	input, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		_ = inputWriter.Close()
	})
	cfg := ConfigureReadlineHistory(&readline.Config{
		Prompt:             "xpf> ",
		Stdin:              input,
		Stdout:             io.Discard,
		Stderr:             io.Discard,
		FuncMakeRaw:        func() error { return nil },
		FuncExitRaw:        func() error { return nil },
		FuncGetWidth:       func() int { return 80 },
		FuncOnWidthChanged: func(func()) {},
	})
	_ = historyFile // file wiring is exercised via Record/Seed helpers below
	rl, err := readline.NewEx(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rl.Close() })
	if err := SeedHistory(rl, seed); err != nil {
		t.Fatalf("seed history: %v", err)
	}
	return rl, inputWriter
}

// feed writes one interactive session script (lines and raw key bytes such
// as ESC [ A for Up) to the readline pipe, then closes it so the final
// Readline observes EOF.
func feed(t *testing.T, w *os.File, script string) {
	t.Helper()
	if _, err := io.WriteString(w, script); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

const keyUp = "\x1b[A"

// TestHistoryRecallSeededSubmitDupEmpty_15284 is the #15284 regression.
// Seeded history: submit a NEW command -> Up must recall IT (not the last
// seeded entry); submit the SAME command again (duplicate) -> Up must
// recall it (not the empty editing slot the old DisableAutoSaveHistory bug
// manufactured, whose Ctrl-D read as EOF/exit); an empty submit must not
// displace recall either. Each recalled line is observed as the value the
// NEXT Readline returns after Up+Enter.
func TestHistoryRecallSeededSubmitDupEmpty_15284(t *testing.T) {
	historyFile := filepath.Join(t.TempDir(), "history")
	rl, w := newHistoryReadline(t, historyFile, []string{"show version", "show interfaces"})

	// Submit new, submit it again (dup), submit empty, then:
	//   Up+Enter (recall newest), Up+Enter again after resubmitting it.
	script := "show clock\n" + // new command
		"show clock\n" + // duplicate submit
		"\n" + // empty submit: must not create an empty recall slot
		keyUp + "\n" + // Up -> "show clock", Enter submits it
		keyUp + "\n" // Up after the resubmit -> "show clock" again, not ""
	feed(t, w, script)

	var got []string
	for {
		line, err := rl.Readline()
		if err != nil {
			break // EOF after script exhausted
		}
		got = append(got, line)
		if err := RecordHistoryLine(historyFile, line); err != nil {
			t.Fatalf("record history: %v", err)
		}
	}
	want := []string{"show clock", "show clock", "", "show clock", "show clock"}
	if len(got) != len(want) {
		t.Fatalf("readline lines = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d = %q, want %q (full: %q)", i, got[i], want[i], got)
		}
	}
	// The recalled duplicate must be the command, never the empty slot:
	// got[3] and got[4] above are the Up-recall assertions (non-empty).
	data, err := os.ReadFile(historyFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "show clock\n") != 4 {
		t.Fatalf("persisted history = %q, want 4x show clock (2 submits + 2 recalls)", data)
	}
}

// TestHistoryPersistsAcrossSessions_15284: a non-sensitive command recorded
// in one session is seeded into the next and recalled with Up.
func TestHistoryPersistsAcrossSessions_15284(t *testing.T) {
	historyFile := filepath.Join(t.TempDir(), "history")
	if err := SecureReadlineHistory(historyFile); err != nil {
		t.Fatal(err)
	}

	rl1, w1 := newHistoryReadline(t, historyFile, nil)
	feed(t, w1, "show version\n")
	line, err := rl1.Readline()
	if err != nil || line != "show version" {
		t.Fatalf("session1 read = (%q,%v)", line, err)
	}
	if err := RecordHistoryLine(historyFile, line); err != nil {
		t.Fatal(err)
	}
	_ = rl1.Close()

	seed, err := ReadHistorySeed(historyFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 1 || seed[0] != "show version" {
		t.Fatalf("seed = %q, want [show version]", seed)
	}

	rl2, w2 := newHistoryReadline(t, historyFile, seed)
	feed(t, w2, keyUp+"\n")
	line, err = rl2.Readline()
	if err != nil {
		t.Fatalf("session2 recall read: %v", err)
	}
	if line != "show version" {
		t.Fatalf("session2 Up recalled %q, want %q", line, "show version")
	}
}

// #10743+#10908: credential lines never reach disk (but DO stay recallable
// in-session), and the history file stays 0600. This replaces the old
// DisableAutoSaveHistory-based test, which passed precisely because of the
// #15284 bug (nothing at all was committed, in memory or on disk).
func TestReadlineHistoryDoesNotPersistSubmittedPSK_10743(t *testing.T) {
	const secretCommand = "set security ike policy pol1 pre-shared-key ascii-text LEAK-READLINE-PSK"

	historyFile := filepath.Join(t.TempDir(), "history")
	if err := os.WriteFile(historyFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(historyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SecureReadlineHistory(historyFile); err != nil {
		t.Fatalf("secure history file: %v", err)
	}
	mode, err := os.Stat(historyFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := mode.Mode().Perm(); got != 0o600 {
		t.Fatalf("history mode before readline open = %04o, want 0600", got)
	}

	rl, w := newHistoryReadline(t, historyFile, nil)
	// Submit the secret, then Up+Enter: in-memory recall MUST return it
	// (recall is not disclosure; only the file is). Then a benign command.
	feed(t, w, secretCommand+"\n"+keyUp+"\n"+"show version\n")

	got1, err := rl.Readline()
	if err != nil || got1 != secretCommand {
		t.Fatalf("submit = (%q,%v), want secret command", got1, err)
	}
	if err := RecordHistoryLine(historyFile, got1); err != nil {
		t.Fatal(err)
	}
	got2, err := rl.Readline()
	if err != nil {
		t.Fatalf("recall read: %v", err)
	}
	if got2 != secretCommand {
		t.Fatalf("Up recalled %q, want the just-submitted secret command (in-memory recall)", got2)
	}
	if err := RecordHistoryLine(historyFile, got2); err != nil {
		t.Fatal(err)
	}
	got3, err := rl.Readline()
	if err != nil || got3 != "show version" {
		t.Fatalf("benign = (%q,%v)", got3, err)
	}
	if err := RecordHistoryLine(historyFile, got3); err != nil {
		t.Fatal(err)
	}
	if err := rl.Close(); err != nil {
		t.Fatalf("close readline: %v", err)
	}
	mode, err = os.Stat(historyFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := mode.Mode().Perm(); got != 0o600 {
		t.Fatalf("history mode after session = %04o, want 0600", got)
	}
	history, err := os.ReadFile(historyFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(history), "LEAK-READLINE-PSK") {
		t.Fatalf("credential line persisted to history file: %q", history)
	}
	if string(history) != "show version\n" {
		t.Fatalf("history file = %q, want only the benign line", history)
	}
	// And the secret must not be seeded back into a later session.
	seed, err := ReadHistorySeed(historyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range seed {
		if strings.Contains(s, "LEAK") {
			t.Fatalf("sensitive line seeded back: %q", seed)
		}
	}
}

func TestIsSensitiveHistoryLine_15284(t *testing.T) {
	sensitive := []string{
		"set security ike policy p pre-shared-key ascii-text hunter2",
		"set security ike policy p pre-shared-key hexadecimal deadbeef",
		"set system root-authentication encrypted-password $6$hash",
		"set system login user u authentication encrypted-password $6$hash",
		"set snmp community mysecret authorization read-only",
		"set system services web-management api-auth key k1 secret hunter2",
		"set system services dynamic-dns provider p password hunter2",
		"set protocols ospf area 0 interface ge-0/0/0 authentication md5 1 key hunter2",
		"set services rpm probe p test t http authentication-password hunter2",
	}
	for _, line := range sensitive {
		if !IsSensitiveHistoryLine(line) {
			t.Errorf("IsSensitiveHistoryLine(%q) = false, want true", line)
		}
	}
	benign := []string{
		"show version",
		"show interfaces terse",
		"set system host-name password123", // value happens to contain the substring; not a token
		"show security ike security-associations",
		"set interfaces ge-0/0/0 unit 0 description key-account",
	}
	for _, line := range benign {
		if IsSensitiveHistoryLine(line) {
			t.Errorf("IsSensitiveHistoryLine(%q) = true, want false", line)
		}
	}
}

func TestAnnotateCommentEscapesRoundTrip13628(t *testing.T) {
	for _, want := range []string{
		`say "hi" team`,
		`a"b`,
		`a\"b`,
		`ends \`,
		`C:\temp`,
		"",
		"plain comment",
	} {
		wire := `system host-name "` + EscapeAnnotateComment(want) + `"`
		path, got, ok := AnnotateCommentFromLine(wire)
		if !ok || path != "system host-name" || got != want {
			t.Errorf("AnnotateCommentFromLine(%q) = (%q, %q, %v), want (%q, %q, true)",
				wire, path, got, ok, "system host-name", want)
		}
	}
}
