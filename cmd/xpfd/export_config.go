package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/upgrade"
)

// #10736: `xpfd export-config` renders the CURRENT DB-canonical active
// configuration as hierarchical text (the same text `show configuration`
// shows and the day-0 loader ingests) and writes it to an operator-named
// file. It exists because the documented image-replace upgrade named
// /etc/xpf/xpf.conf as the portable artifact, but that boot file is written
// once at install and never rewritten after the store became DB-canonical
// (pkg/daemon/daemon_flow.go #3867) — carrying it to the replacement box
// silently reverts every commit since install. The export this verb writes
// is the artifact the corrected runbooks carry instead.
//
// Read-only against the live DB: it opens the config DB exactly the way the
// #1917 cut's control-socket probe does (configstore.NewDB + ReadActive —
// active.json is written by atomic rename, so a concurrent commit yields
// the old or the new tree, never a torn one) and never mutates store state.

// exportConfigFlags holds the parsed `xpfd export-config` argument set. Kept
// in a struct so the parsing is unit-testable without the os.Exit /
// filesystem side effects of the dispatch (the parseUpgradeArgs #4869 /
// parseCleanupArgs #5322 precedent).
type exportConfigFlags struct {
	configDBDir string
	outPath     string
}

// parseExportConfigArgs parses `xpfd export-config [--configdb-dir DIR]
// <output-file>`.
//
// Fail-closed like the sibling parsers: a missing or extra positional operand
// is a hard usage error, never a default run. `-` (stdout) is refused: the
// export carries cleartext secrets, and a stdout spray lands in terminal
// scrollback, CI logs, or a deploy harness transcript — the artifact must be
// an explicit 0600 file.
func parseExportConfigArgs(args []string) (exportConfigFlags, error) {
	fs := flag.NewFlagSet("export-config", flag.ContinueOnError)
	configDBDir := fs.String("configdb-dir", upgrade.DefaultConfigDBDir,
		"config DB dir to export the active configuration from")
	if err := fs.Parse(args); err != nil {
		return exportConfigFlags{}, err
	}
	if fs.NArg() != 1 {
		return exportConfigFlags{}, fmt.Errorf(
			"usage: xpfd export-config [--configdb-dir DIR] <output-file> (got %d positional argument(s))",
			fs.NArg())
	}
	out := fs.Arg(0)
	if out == "" {
		return exportConfigFlags{}, fmt.Errorf("usage: xpfd export-config [--configdb-dir DIR] <output-file> (empty output path)")
	}
	if out == "-" {
		return exportConfigFlags{}, fmt.Errorf(
			"refusing to write the active configuration to stdout: it carries cleartext secrets; name an explicit output file (written 0600)")
	}
	return exportConfigFlags{configDBDir: *configDBDir, outPath: out}, nil
}

// exportActiveConfig writes the CURRENT active configuration from the config
// DB at configDBDir to outPath as hierarchical day-0-format text.
//
// Fail-closed: a missing/non-directory DB dir errors (it is stat'ed first so
// this read-only verb never CREATES store state via NewDB's MkdirAll), an
// absent or empty active tree errors (there is nothing to carry — a fresh
// image boots factory-default without an artifact), and the parent directory
// of outPath must already exist (no MkdirAll on operator-supplied paths).
// The write is atomic (temp sibling + rename, so a reader never observes a
// torn file and a symlinked outPath is REPLACED, never followed) and 0600 —
// the active config may carry credential material.
func exportActiveConfig(configDBDir, outPath string) error {
	if outPath == "" {
		return fmt.Errorf("empty output path")
	}
	fi, err := os.Stat(configDBDir)
	if err != nil {
		return fmt.Errorf("config db dir %s: %w (nothing to export)", configDBDir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("config db dir %s is not a directory", configDBDir)
	}
	if parent := filepath.Dir(outPath); parent != "" {
		if pi, perr := os.Stat(parent); perr != nil || !pi.IsDir() {
			return fmt.Errorf("output directory %s does not exist (not created)", parent)
		}
	}
	db, err := configstore.NewDB(configDBDir)
	if err != nil {
		return fmt.Errorf("open config db %s: %w", configDBDir, err)
	}
	tree, err := db.ReadActive()
	if err != nil {
		return fmt.Errorf("read active configuration from %s: %w", configDBDir, err)
	}
	if tree == nil {
		return fmt.Errorf("no active configuration in %s (nothing to export)", configDBDir)
	}
	text := tree.Format()
	if text == "" {
		return fmt.Errorf("active configuration in %s is empty (nothing to export)", configDBDir)
	}
	if err := fsatomic.WriteFileAtomic(outPath, []byte(text), 0600); err != nil {
		return fmt.Errorf("write export %s: %w", outPath, err)
	}
	return nil
}

// runExportConfigSubcommand executes `xpfd export-config` with process exit
// semantics (usage/config errors to stderr, exit 1), mirroring
// runUpgradeSubcommand.
func runExportConfigSubcommand(args []string) {
	flags, err := parseExportConfigArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "export-config: %v\n", err)
		os.Exit(1)
	}
	if err := exportActiveConfig(flags.configDBDir, flags.outPath); err != nil {
		fmt.Fprintf(os.Stderr, "export-config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("exported current active configuration to %s (0600)\n", flags.outPath)
}
