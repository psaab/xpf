package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/daemon"
)

const daemonTestName5809 = "/opt/xpf-test/bin/xpfd"

type recordingDaemonRunner5809 struct {
	calls int
	ctx   context.Context
	err   error
}

func (r *recordingDaemonRunner5809) Run(ctx context.Context) error {
	r.calls++
	r.ctx = ctx
	return r.err
}

func daemonUsageGolden5809(name string) string {
	return fmt.Sprintf("Usage of %s:\n"+
		"  -api-addr string\n"+
		"    \tHTTP API listen address (empty to disable) (default \"127.0.0.1:8080\")\n"+
		"  -cold-path-sample-mask uint\n"+
		"    \tCold-path latency histogram sample mask (powers-of-two minus one). Default 0xff = 1-in-256 sampling. Allowed values: 0x1, 0x3, 0x7, 0xff, 0x3ff, ..., 0x7fffffffffffffff. For 1-in-1 sampling (256× CPU cost — bounded-cohort microbench only), use --enable-cold-path-1-in-1-sampling. (default 255)\n"+
		"  -config string\n"+
		"    \tconfiguration file path (default \"/etc/xpf/xpf.conf\")\n"+
		"  -debug\n"+
		"    \tenable debug logging\n"+
		"  -enable-cold-path-1-in-1-sampling\n"+
		"    \tEnable 1-in-1 cold-path latency sampling (256× CPU cost). Required for bounded-cohort microbench (#1622); never use in production. Overrides --cold-path-sample-mask to 0.\n"+
		"  -grpc-addr string\n"+
		"    \tgRPC API listen address (default \"127.0.0.1:50051\")\n"+
		"  -no-dataplane\n"+
		"    \trun without a dataplane (config-only mode)\n", name)
}

func TestParseDaemonArgsDefaultsAndFlags5809(t *testing.T) {
	defaults := parseDaemonArgs(daemonTestName5809, nil)
	if defaults.kind != daemonResultOK || defaults.err != nil || defaults.flagOutput != "" {
		t.Fatalf("default parse result = %+v, want clean OK", defaults)
	}
	if defaults.flags.configFile != "/etc/xpf/xpf.conf" || defaults.flags.noDataplane ||
		defaults.flags.apiAddr != "127.0.0.1:8080" ||
		defaults.flags.grpcAddr != "127.0.0.1:50051" || defaults.flags.debug ||
		defaults.flags.coldPathSampleMask != nil {
		t.Fatalf("default flags = %+v, want daemon defaults with nil cold-path override", defaults.flags)
	}

	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, got daemonFlags)
	}{
		{
			name: "config separated",
			args: []string{"--config", "/tmp/xpf.conf"},
			check: func(t *testing.T, got daemonFlags) {
				if got.configFile != "/tmp/xpf.conf" {
					t.Fatalf("configFile = %q", got.configFile)
				}
			},
		},
		{
			name: "config equals",
			args: []string{"--config=/tmp/xpf-equals.conf"},
			check: func(t *testing.T, got daemonFlags) {
				if got.configFile != "/tmp/xpf-equals.conf" {
					t.Fatalf("configFile = %q", got.configFile)
				}
			},
		},
		{
			name: "no dataplane",
			args: []string{"--no-dataplane"},
			check: func(t *testing.T, got daemonFlags) {
				if !got.noDataplane {
					t.Fatal("noDataplane = false")
				}
			},
		},
		{
			name: "api address",
			args: []string{"--api-addr", ""},
			check: func(t *testing.T, got daemonFlags) {
				if got.apiAddr != "" {
					t.Fatalf("apiAddr = %q", got.apiAddr)
				}
			},
		},
		{
			name: "grpc address equals",
			args: []string{"--grpc-addr=127.0.0.2:6000"},
			check: func(t *testing.T, got daemonFlags) {
				if got.grpcAddr != "127.0.0.2:6000" {
					t.Fatalf("grpcAddr = %q", got.grpcAddr)
				}
			},
		},
		{
			name: "debug",
			args: []string{"--debug"},
			check: func(t *testing.T, got daemonFlags) {
				if !got.debug {
					t.Fatal("debug = false")
				}
			},
		},
		{
			name: "sample mask",
			args: []string{"--cold-path-sample-mask", "0x3"},
			check: func(t *testing.T, got daemonFlags) {
				if got.coldPathSampleMask == nil || *got.coldPathSampleMask != 3 {
					t.Fatalf("coldPathSampleMask = %v, want 3", got.coldPathSampleMask)
				}
			},
		},
		{
			name: "explicit one in one false is authored",
			args: []string{"--enable-cold-path-1-in-1-sampling=false"},
			check: func(t *testing.T, got daemonFlags) {
				if got.coldPathSampleMask == nil || *got.coldPathSampleMask != 0xff {
					t.Fatalf("coldPathSampleMask = %v, want authored default 255", got.coldPathSampleMask)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDaemonArgs(daemonTestName5809, tt.args)
			if result.kind != daemonResultOK || result.err != nil {
				t.Fatalf("parseDaemonArgs(%q) = kind %d, err %v", tt.args, result.kind, result.err)
			}
			tt.check(t, result.flags)
		})
	}
}

func TestParseDaemonArgsColdPathMatrix5809(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantKind  daemonResultKind
		wantMask  uint64
		wantNil   bool
		wantError string
	}{
		{name: "omitted", wantKind: daemonResultOK, wantNil: true},
		{name: "explicit default", args: []string{"--cold-path-sample-mask=0xff"}, wantKind: daemonResultOK, wantMask: 0xff},
		{name: "explicit false", args: []string{"--enable-cold-path-1-in-1-sampling=false"}, wantKind: daemonResultOK, wantMask: 0xff},
		{name: "enable", args: []string{"--enable-cold-path-1-in-1-sampling"}, wantKind: daemonResultOK, wantMask: 0},
		{name: "enable overrides mask", args: []string{"--cold-path-sample-mask=0x3", "--enable-cold-path-1-in-1-sampling"}, wantKind: daemonResultOK, wantMask: 0},
		{name: "zero requires enable", args: []string{"--cold-path-sample-mask=0"}, wantKind: daemonResultSemanticError, wantNil: true, wantError: "requires explicit"},
		{name: "minimum", args: []string{"--cold-path-sample-mask=0x1"}, wantKind: daemonResultOK, wantMask: 1},
		{name: "maximum accepted", args: []string{"--cold-path-sample-mask=0x7fffffffffffffff"}, wantKind: daemonResultOK, wantMask: 0x7fffffffffffffff},
		{name: "not power minus one", args: []string{"--cold-path-sample-mask=2"}, wantKind: daemonResultSemanticError, wantNil: true, wantError: "power-of-two minus one"},
		{name: "uint64 max ambiguous", args: []string{"--cold-path-sample-mask=0xffffffffffffffff"}, wantKind: daemonResultSemanticError, wantNil: true, wantError: "u64::MAX"},
		{name: "uint64 overflow", args: []string{"--cold-path-sample-mask=0x10000000000000000"}, wantKind: daemonResultFlagError, wantNil: true, wantError: "value out of range"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDaemonArgs(daemonTestName5809, tt.args)
			if result.kind != tt.wantKind {
				t.Fatalf("kind = %d, want %d (err %v)", result.kind, tt.wantKind, result.err)
			}
			if tt.wantNil {
				if result.flags.coldPathSampleMask != nil {
					t.Fatalf("mask = %v, want nil", result.flags.coldPathSampleMask)
				}
			} else if result.flags.coldPathSampleMask == nil || *result.flags.coldPathSampleMask != tt.wantMask {
				t.Fatalf("mask = %v, want %d", result.flags.coldPathSampleMask, tt.wantMask)
			}
			if tt.wantError != "" {
				combined := result.flagOutput
				if result.err != nil {
					combined += result.err.Error()
				}
				if !bytes.Contains([]byte(combined), []byte(tt.wantError)) {
					t.Fatalf("error/output %q does not contain %q", combined, tt.wantError)
				}
				return
			}
			if result.err != nil {
				t.Fatalf("unexpected error: %v", result.err)
			}
		})
	}
}

func TestParseDaemonArgsHelpAndFlagOutput5809(t *testing.T) {
	usage := daemonUsageGolden5809(daemonTestName5809)
	tests := []struct {
		name       string
		args       []string
		wantKind   daemonResultKind
		wantOutput string
		wantCode   int
	}{
		{name: "short help", args: []string{"-h"}, wantKind: daemonResultHelp, wantOutput: usage, wantCode: 0},
		{name: "long help", args: []string{"--help"}, wantKind: daemonResultHelp, wantOutput: usage, wantCode: 0},
		{name: "help wins before remainder", args: []string{"--help", "cleanup"}, wantKind: daemonResultHelp, wantOutput: usage, wantCode: 0},
		{name: "unknown flag", args: []string{"--unknown"}, wantKind: daemonResultFlagError, wantOutput: "flag provided but not defined: -unknown\n" + usage, wantCode: 2},
		{name: "missing value", args: []string{"--config"}, wantKind: daemonResultFlagError, wantOutput: "flag needs an argument: -config\n" + usage, wantCode: 2},
		{name: "invalid boolean", args: []string{"--debug=maybe"}, wantKind: daemonResultFlagError, wantOutput: "invalid boolean value \"maybe\" for -debug: parse error\n" + usage, wantCode: 2},
		{name: "invalid uint", args: []string{"--cold-path-sample-mask=nope"}, wantKind: daemonResultFlagError, wantOutput: "invalid value \"nope\" for flag -cold-path-sample-mask: parse error\n" + usage, wantCode: 2},
		{name: "uint overflow", args: []string{"--cold-path-sample-mask=0x10000000000000000"}, wantKind: daemonResultFlagError, wantOutput: "invalid value \"0x10000000000000000\" for flag -cold-path-sample-mask: value out of range\n" + usage, wantCode: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDaemonArgs(daemonTestName5809, tt.args)
			if result.kind != tt.wantKind {
				t.Fatalf("kind = %d, want %d", result.kind, tt.wantKind)
			}
			if tt.wantKind == daemonResultHelp && !errors.Is(result.err, flag.ErrHelp) {
				t.Fatalf("help error = %v, want flag.ErrHelp", result.err)
			}
			if result.flagOutput != tt.wantOutput {
				t.Fatalf("flag output mismatch\n--- got ---\n%s--- want ---\n%s", result.flagOutput, tt.wantOutput)
			}
			var reported bytes.Buffer
			if code := reportDaemonResult(&reported, result); code != tt.wantCode {
				t.Fatalf("report code = %d, want %d", code, tt.wantCode)
			}
			if reported.String() != tt.wantOutput {
				t.Fatalf("reported output mismatch or duplicate\n--- got ---\n%s--- want ---\n%s", reported.String(), tt.wantOutput)
			}
		})
	}
}

func TestParseDaemonArgsSemanticOutput5809(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name: "zero without explicit enable",
			args: []string{"--cold-path-sample-mask=0"},
			wantErr: "--cold-path-sample-mask=0 requires explicit " +
				"--enable-cold-path-1-in-1-sampling (256× CPU cost — " +
				"bounded-cohort microbench only)",
		},
		{
			name: "non power minus one",
			args: []string{"--cold-path-sample-mask=2"},
			wantErr: "--cold-path-sample-mask=0x2: must be a power-of-two " +
				"minus one (0x1, 0x3, 0x7, 0xff, 0x3ff, ..., 0x7fff_ffff_ffff_ffff) " +
				"or 0 with --enable-cold-path-1-in-1-sampling. Rejecting " +
				"u64::MAX as ambiguous.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDaemonArgs(daemonTestName5809, tt.args)
			if result.kind != daemonResultSemanticError || result.err == nil || result.err.Error() != tt.wantErr {
				t.Fatalf("semantic result = kind %d, err %q; want %q", result.kind, result.err, tt.wantErr)
			}
			if result.flagOutput != "" {
				t.Fatalf("flagOutput = %q, want empty", result.flagOutput)
			}
			var reported bytes.Buffer
			if code := reportDaemonResult(&reported, result); code != 1 {
				t.Fatalf("report code = %d, want 1", code)
			}
			if got := reported.String(); got != "xpfd: "+tt.wantErr+"\n" {
				t.Fatalf("reported = %q, want %q", got, "xpfd: "+tt.wantErr+"\n")
			}
		})
	}
}

func TestParseDaemonArgsRemainders5809(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		remainder []string
	}{
		{name: "debug cleanup", args: []string{"--debug", "cleanup"}, remainder: []string{"cleanup"}},
		{name: "config version", args: []string{"--config", "/tmp/xpf.conf", "version"}, remainder: []string{"version"}},
		{name: "show system", args: []string{"--no-dataplane", "show", "system"}, remainder: []string{"show", "system"}},
		{name: "unknown plus later flag", args: []string{"unknown", "--debug"}, remainder: []string{"unknown", "--debug"}},
		{name: "multiple", args: []string{"one", "two", "three"}, remainder: []string{"one", "two", "three"}},
		{name: "empty", args: []string{""}, remainder: []string{""}},
		{name: "space", args: []string{" "}, remainder: []string{" "}},
		{name: "control", args: []string{"\t\n"}, remainder: []string{"\t\n"}},
		{name: "quote and backslash", args: []string{"a\"b\\c"}, remainder: []string{"a\"b\\c"}},
		{name: "lone dash", args: []string{"-"}, remainder: []string{"-"}},
		{name: "post terminator empty", args: []string{"--", ""}, remainder: []string{""}},
		{name: "post terminator dash", args: []string{"--", "-"}, remainder: []string{"-"}},
		{name: "post terminator flag", args: []string{"--", "--debug"}, remainder: []string{"--debug"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDaemonArgs(daemonTestName5809, tt.args)
			if result.kind != daemonResultRemainderError {
				t.Fatalf("kind = %d, want remainder error (err %v)", result.kind, result.err)
			}
			want := fmt.Sprintf("unexpected argument(s) %q; subcommands must be the first argument; usage: %s [daemon flags]", tt.remainder, daemonTestName5809)
			if result.err == nil || result.err.Error() != want {
				t.Fatalf("error = %q, want %q", result.err, want)
			}
			if result.flagOutput != "" {
				t.Fatalf("flagOutput = %q, want empty", result.flagOutput)
			}
			var reported bytes.Buffer
			if code := reportDaemonResult(&reported, result); code != 1 {
				t.Fatalf("report code = %d, want 1", code)
			}
			if got := reported.String(); got != "xpfd: "+want+"\n" {
				t.Fatalf("reported = %q", got)
			}
		})
	}

	if result := parseDaemonArgs(daemonTestName5809, []string{"--"}); result.kind != daemonResultOK || result.err != nil {
		t.Fatalf("bare -- = kind %d, err %v; want OK", result.kind, result.err)
	}
}

func TestRunDaemonInvalidInputHasNoSideEffects5809(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })

	tests := []struct {
		name string
		args []string
		kind daemonResultKind
	}{
		{name: "short help", args: []string{"-h"}, kind: daemonResultHelp},
		{name: "long help", args: []string{"--help"}, kind: daemonResultHelp},
		{name: "help before remainder", args: []string{"--help", "cleanup"}, kind: daemonResultHelp},
		{name: "unknown flag", args: []string{"--unknown"}, kind: daemonResultFlagError},
		{name: "missing value", args: []string{"--config"}, kind: daemonResultFlagError},
		{name: "invalid boolean", args: []string{"--debug=maybe"}, kind: daemonResultFlagError},
		{name: "invalid uint", args: []string{"--cold-path-sample-mask=nope"}, kind: daemonResultFlagError},
		{name: "uint overflow", args: []string{"--cold-path-sample-mask=0x10000000000000000"}, kind: daemonResultFlagError},
		{name: "debug cleanup", args: []string{"--debug", "cleanup"}, kind: daemonResultRemainderError},
		{name: "config version", args: []string{"--config", "/tmp/xpf.conf", "version"}, kind: daemonResultRemainderError},
		{name: "show system", args: []string{"--no-dataplane", "show", "system"}, kind: daemonResultRemainderError},
		{name: "unknown plus later flag", args: []string{"unknown", "--debug"}, kind: daemonResultRemainderError},
		{name: "multiple remainder", args: []string{"one", "two", "three"}, kind: daemonResultRemainderError},
		{name: "empty remainder", args: []string{""}, kind: daemonResultRemainderError},
		{name: "space remainder", args: []string{" "}, kind: daemonResultRemainderError},
		{name: "control remainder", args: []string{"\t\n"}, kind: daemonResultRemainderError},
		{name: "quote and backslash remainder", args: []string{"a\"b\\c"}, kind: daemonResultRemainderError},
		{name: "lone dash remainder", args: []string{"-"}, kind: daemonResultRemainderError},
		{name: "post terminator empty", args: []string{"--", ""}, kind: daemonResultRemainderError},
		{name: "post terminator dash", args: []string{"--", "-"}, kind: daemonResultRemainderError},
		{name: "post terminator flag", args: []string{"--", "--debug"}, kind: daemonResultRemainderError},
		{name: "zero without enable", args: []string{"--cold-path-sample-mask=0"}, kind: daemonResultSemanticError},
		{name: "non power minus one", args: []string{"--cold-path-sample-mask=2"}, kind: daemonResultSemanticError},
		{name: "uint64 max ambiguous", args: []string{"--cold-path-sample-mask=0xffffffffffffffff"}, kind: daemonResultSemanticError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sentinel := slog.New(slog.NewTextHandler(io.Discard, nil))
			slog.SetDefault(sentinel)
			factoryCalls := 0
			runner := &recordingDaemonRunner5809{}
			result := runDaemon(daemonTestName5809, tt.args, "test-version", io.Discard,
				func(daemon.Options) (daemonRunner, error) {
					factoryCalls++
					return runner, nil
				})
			if result.kind != tt.kind {
				t.Fatalf("kind = %d, want %d", result.kind, tt.kind)
			}
			if factoryCalls != 0 {
				t.Fatalf("factory called %d times", factoryCalls)
			}
			if runner.calls != 0 {
				t.Fatalf("runner called %d times", runner.calls)
			}
			if slog.Default() != sentinel {
				t.Fatal("invalid input changed slog.Default")
			}
		})
	}
}

func TestRunDaemonExecution5809(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })

	tests := []struct {
		name      string
		args      []string
		wantDebug bool
		checkOpts func(t *testing.T, got daemon.Options)
	}{
		{
			name: "defaults info logger",
			checkOpts: func(t *testing.T, got daemon.Options) {
				if got.ConfigFile != "/etc/xpf/xpf.conf" ||
					got.APIAuthArchiveMigrationDir != configstore.DefaultArchiveDir ||
					got.NoDataplane || got.APIAddr != "127.0.0.1:8080" ||
					got.GRPCAddr != "127.0.0.1:50051" || got.Version != "test-version" ||
					got.ColdPathSampleMask != nil {
					t.Fatalf("default options = %+v", got)
				}
			},
		},
		{
			name: "all fields debug logger",
			args: []string{
				"--config=/tmp/daemon.conf",
				"--no-dataplane",
				"--api-addr=",
				"--grpc-addr=127.0.0.2:6000",
				"--debug",
				"--cold-path-sample-mask=0x3",
			},
			wantDebug: true,
			checkOpts: func(t *testing.T, got daemon.Options) {
				if got.ConfigFile != "/tmp/daemon.conf" || got.APIAuthArchiveMigrationDir != "" ||
					!got.NoDataplane || got.APIAddr != "" || got.GRPCAddr != "127.0.0.2:6000" ||
					got.Version != "test-version" || got.ColdPathSampleMask == nil ||
					*got.ColdPathSampleMask != 3 {
					t.Fatalf("all-field options = %+v", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotOpts daemon.Options
			factoryCalls := 0
			runner := &recordingDaemonRunner5809{}
			result := runDaemon(daemonTestName5809, tt.args, "test-version", io.Discard,
				func(opts daemon.Options) (daemonRunner, error) {
					factoryCalls++
					gotOpts = opts
					return runner, nil
				})
			if result.kind != daemonResultOK || result.err != nil {
				t.Fatalf("run result = kind %d, err %v", result.kind, result.err)
			}
			if factoryCalls != 1 || runner.calls != 1 {
				t.Fatalf("factory calls = %d, runner calls = %d", factoryCalls, runner.calls)
			}
			if runner.ctx != context.Background() {
				t.Fatalf("runner context = %v, want context.Background", runner.ctx)
			}
			if got := slog.Default().Enabled(context.Background(), slog.LevelDebug); got != tt.wantDebug {
				t.Fatalf("debug enabled = %v, want %v", got, tt.wantDebug)
			}
			tt.checkOpts(t, gotOpts)
			var reported bytes.Buffer
			if code := reportDaemonResult(&reported, result); code != 0 || reported.Len() != 0 {
				t.Fatalf("success report = code %d, output %q", code, reported.String())
			}
		})
	}
}

func TestRunDaemonFactoryAndRunnerErrors5809(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })

	factoryErr := errors.New("factory failed")
	factoryCalls := 0
	factoryRunner := &recordingDaemonRunner5809{}
	result := runDaemon(daemonTestName5809, nil, "test-version", io.Discard,
		func(daemon.Options) (daemonRunner, error) {
			factoryCalls++
			return factoryRunner, factoryErr
		})
	if result.kind != daemonResultFactoryError || !errors.Is(result.err, factoryErr) ||
		factoryCalls != 1 || factoryRunner.calls != 0 {
		t.Fatalf("factory result = %+v, calls %d, runner calls %d", result, factoryCalls, factoryRunner.calls)
	}
	var reported bytes.Buffer
	if code := reportDaemonResult(&reported, result); code != 1 || reported.String() != "xpfd: factory failed\n" {
		t.Fatalf("factory report = code %d, output %q", code, reported.String())
	}

	runErr := errors.New("runner failed")
	runner := &recordingDaemonRunner5809{err: runErr}
	factoryCalls = 0
	result = runDaemon(daemonTestName5809, nil, "test-version", io.Discard,
		func(daemon.Options) (daemonRunner, error) {
			factoryCalls++
			return runner, nil
		})
	if result.kind != daemonResultRunError || !errors.Is(result.err, runErr) ||
		factoryCalls != 1 || runner.calls != 1 || runner.ctx != context.Background() {
		t.Fatalf("runner result = %+v, factory calls %d, runner %+v", result, factoryCalls, runner)
	}
	reported.Reset()
	if code := reportDaemonResult(&reported, result); code != 1 || reported.String() != "xpfd: runner failed\n" {
		t.Fatalf("runner report = code %d, output %q", code, reported.String())
	}
}

func TestDaemonMainSubprocess5809(t *testing.T) {
	scenario := os.Getenv("XPF_DAEMON_MAIN_SCENARIO_5809")
	if scenario == "" {
		return
	}

	argv0 := os.Getenv("XPF_DAEMON_MAIN_ARGV0_5809")
	switch scenario {
	case "remainder":
		os.Args = []string{argv0, "--config", os.Getenv("XPF_DAEMON_MAIN_CONFIG_5809"), "version"}
		main()
		os.Exit(99)
	case "help":
		os.Args = []string{argv0, "--help"}
		main()
		os.Exit(0)
	default:
		os.Exit(98)
	}
}

func TestDaemonMainProductionBoundary5809(t *testing.T) {
	argv0 := "/opt/xpf test/bin/xpfd"
	blockedParent := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blockedParent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	blockedConfig := filepath.Join(blockedParent, "xpf.conf")

	run := func(t *testing.T, scenario string) (string, string, int) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestDaemonMainSubprocess5809$")
		cmd.Env = append(os.Environ(),
			"XPF_DAEMON_MAIN_SCENARIO_5809="+scenario,
			"XPF_DAEMON_MAIN_ARGV0_5809="+argv0,
			"XPF_DAEMON_MAIN_CONFIG_5809="+blockedConfig,
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err == nil {
			return stdout.String(), stderr.String(), 0
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("subprocess error = %v", err)
		}
		return stdout.String(), stderr.String(), exitErr.ExitCode()
	}

	t.Run("late version is rejected before daemon construction", func(t *testing.T) {
		stdout, stderr, code := run(t, "remainder")
		want := fmt.Sprintf("xpfd: unexpected argument(s) [\"version\"]; subcommands must be the first argument; usage: %s [daemon flags]\n", argv0)
		if code != 1 || stdout != "" || stderr != want {
			t.Fatalf("code=%d stdout=%q stderr=%q, want code=1 stdout empty stderr=%q", code, stdout, stderr, want)
		}
	})

	t.Run("help uses production argv zero", func(t *testing.T) {
		stdout, stderr, code := run(t, "help")
		if code != 0 || stdout != "" || stderr != daemonUsageGolden5809(argv0) {
			t.Fatalf("code=%d stdout=%q stderr mismatch=%v", code, stdout, stderr != daemonUsageGolden5809(argv0))
		}
	})
}
