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

func TestReadlineHistoryDoesNotPersistSubmittedPSK_10743(t *testing.T) {
	const secretCommand = "set security ike policy pol1 pre-shared-key ascii-text LEAK-READLINE-PSK"

	input, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		_ = inputWriter.Close()
	})
	if _, err := io.WriteString(inputWriter, secretCommand+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := inputWriter.Close(); err != nil {
		t.Fatal(err)
	}

	historyFile := filepath.Join(t.TempDir(), "history")
	cfg := DisableReadlineHistoryAutoSave(&readline.Config{
		HistoryFile:        historyFile,
		HistoryLimit:       10000,
		Stdin:              input,
		Stdout:             io.Discard,
		Stderr:             io.Discard,
		FuncMakeRaw:        func() error { return nil },
		FuncExitRaw:        func() error { return nil },
		FuncGetWidth:       func() int { return 80 },
		FuncOnWidthChanged: func(func()) {},
	})

	rl, err := readline.NewEx(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()

	got, err := rl.Readline()
	if err != nil {
		t.Fatalf("read submitted CLI line: %v", err)
	}
	if got != secretCommand {
		t.Fatalf("readline returned %q, want %q", got, secretCommand)
	}
	if err := rl.Close(); err != nil {
		t.Fatalf("close readline: %v", err)
	}

	history, err := os.ReadFile(historyFile)
	if err != nil {
		t.Fatalf("read history file: %v", err)
	}
	if strings.Contains(string(history), "LEAK-READLINE-PSK") {
		t.Fatalf("readline persisted a submitted PSK in the history file: %q", history)
	}
}
