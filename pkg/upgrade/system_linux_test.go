package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeVersionBin writes an executable shell script at path that prints
// `out` on `<bin> version` (and exits `exitCode`). Used to drive
// realSystem.BinaryVersion through a real exec without a real xpfd.
func writeFakeVersionBin(t *testing.T, path, out string, exitCode int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// The script echoes the canned output for any args and exits exitCode.
	// Use printf so embedded specials (spaces, control chars) survive.
	script := "#!/bin/sh\nprintf '%s' \"" + shellEscape(out) + "\"\nexit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// shellEscape escapes a string for embedding inside the double-quoted VALUE
// argument of `printf '%s' "<value>"`. The format string is the FIXED first
// arg ('%s'); the value is the second arg and printf emits it literally, so
// `%` must NOT be doubled (AGY r1 — doubling would print `%%`). We only
// neutralize the characters the shell would otherwise interpret inside the
// double quotes: backslash, double-quote, dollar, and backtick.
func shellEscape(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		`$`, `\$`,
		"`", "\\`",
	)
	return r.Replace(s)
}

// TestBinaryVersion_ValidExtracted confirms a well-formed `xpfd <ver> ...`
// output yields the version token unchanged for legitimate Debian/semver
// shapes (#1967 C1 must not break real versions).
func TestBinaryVersion_ValidExtracted(t *testing.T) {
	cases := map[string]string{
		"xpfd 1.2.3 (commit abc, built t)": "1.2.3",
		"xpfd 2.4.1-rc3 (commit x)":        "2.4.1-rc3",
		"xpfd 1.0.0+build.7 (commit y)":    "1.0.0+build.7",
		"xpfd 1:2.3.4-1 (commit z)":        "1:2.3.4-1",
		"xpfd 0.0.1~beta1\n":               "0.0.1~beta1",
		"xpfd v1.2.3":                      "v1.2.3",
		"xpfd dev (commit deadbeef)\n\n":   "dev",
		// A literal '%' in the trailing metadata must survive the test's
		// printf helper unchanged (AGY r1 shellEscape fix); the token itself
		// stays clean.
		"xpfd 1.0.0 (commit 100%coverage)": "1.0.0",
	}
	s := &realSystem{systemdUnitDir: t.TempDir(), unit: "xpfd"}
	dir := t.TempDir()
	i := 0
	for out, want := range cases {
		i++
		bin := filepath.Join(dir, "xpfd"+itoa(i))
		writeFakeVersionBin(t, bin, out, 0)
		got, err := s.BinaryVersion(bin)
		if err != nil {
			t.Errorf("BinaryVersion(out=%q) unexpected error: %v", out, err)
			continue
		}
		if got != want {
			t.Errorf("BinaryVersion(out=%q) = %q, want %q", out, got, want)
		}
	}
}

// TestBinaryVersion_RejectsUnsafeToken confirms a path-escaping or otherwise
// unsafe extracted token hard-fails instead of flowing into versions/<ver>
// (#1967 C1). The token is in field[1] but is not a safe path segment.
func TestBinaryVersion_RejectsUnsafeToken(t *testing.T) {
	bad := []string{
		"xpfd ../../etc (commit x)", // path traversal in the token
		"xpfd a/b (commit x)",       // separator in the token
		"xpfd .hidden (commit x)",   // leading dot (dotfile namespace)
	}
	s := &realSystem{systemdUnitDir: t.TempDir(), unit: "xpfd"}
	dir := t.TempDir()
	for i, out := range bad {
		bin := filepath.Join(dir, "xpfd-bad"+itoa(i))
		writeFakeVersionBin(t, bin, out, 0)
		got, err := s.BinaryVersion(bin)
		if err == nil {
			t.Errorf("BinaryVersion(out=%q) = %q, want error (unsafe token)", out, got)
		}
		if got != "" {
			t.Errorf("BinaryVersion(out=%q) returned non-empty %q on error", out, got)
		}
	}
}

// TestBinaryVersion_RejectsGarbageFormat confirms that output NOT matching
// "xpfd <ver> ..." hard-fails instead of returning the whole trimmed string
// (the old fallback that #1967 C1 removes). A corrupt binary, an arch/lib
// mismatch printing junk, or a renamed first token must NOT become a version.
func TestBinaryVersion_RejectsGarbageFormat(t *testing.T) {
	bad := []string{
		"totally unexpected output", // wrong first field
		"xpfd",                      // only one field, no version
		"some/path/with/slashes and spaces all over", // unstructured garbage
		"Segmentation fault\n",                       // crash-like text
		"",                                           // empty
	}
	s := &realSystem{systemdUnitDir: t.TempDir(), unit: "xpfd"}
	dir := t.TempDir()
	for i, out := range bad {
		bin := filepath.Join(dir, "xpfd-garbage"+itoa(i))
		writeFakeVersionBin(t, bin, out, 0)
		got, err := s.BinaryVersion(bin)
		if err == nil {
			t.Errorf("BinaryVersion(out=%q) = %q, want error (unrecognized format)", out, got)
		}
		if got != "" {
			t.Errorf("BinaryVersion(out=%q) returned non-empty %q on error", out, got)
		}
		// Crucially: the raw garbage must never be returned as a version.
		if got == strings.TrimSpace(out) && strings.TrimSpace(out) != "" {
			t.Errorf("BinaryVersion leaked raw output %q as a version", out)
		}
	}
}

// TestBinaryVersion_ExecFailure confirms a non-zero exec still errors (the
// pre-existing behavior, kept by #1967 C1).
func TestBinaryVersion_ExecFailure(t *testing.T) {
	s := &realSystem{systemdUnitDir: t.TempDir(), unit: "xpfd"}
	bin := filepath.Join(t.TempDir(), "xpfd-fail")
	writeFakeVersionBin(t, bin, "boom", 2)
	if _, err := s.BinaryVersion(bin); err == nil {
		t.Fatal("expected error on non-zero exec, got nil")
	}
}
func TestEnvelopeReaderVersion_ProbeOutput(t *testing.T) {
	s := &realSystem{systemdUnitDir: t.TempDir(), unit: "xpfd"}
	bin := filepath.Join(t.TempDir(), "xpfd-capability")
	writeFakeVersionBin(t, bin, "configdb-envelope-version=2\nconfigdb-min-reader-version=1\n", 0)
	got, err := s.EnvelopeReaderVersion(bin)
	if err != nil {
		t.Fatalf("EnvelopeReaderVersion: %v", err)
	}
	if got != 2 {
		t.Fatalf("EnvelopeReaderVersion = %d, want 2", got)
	}
}

func TestEnvelopeReaderVersion_RefusesMalformedProbe(t *testing.T) {
	s := &realSystem{systemdUnitDir: t.TempDir(), unit: "xpfd"}
	cases := []struct {
		name string
		out  string
		code int
	}{
		{"missing-key", "xpfd capability-check\n", 0},
		{"zero-reader", "configdb-envelope-version=0\n", 0},
		{"exec-failure", "boom\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "xpfd-capability")
			writeFakeVersionBin(t, bin, tc.out, tc.code)
			if got, err := s.EnvelopeReaderVersion(bin); err == nil {
				t.Fatalf("EnvelopeReaderVersion = %d, want error", got)
			}
		})
	}
}

func TestProtocolVersionsProbe14991(t *testing.T) {
	s := &realSystem{systemdUnitDir: t.TempDir(), unit: "xpfd"}
	bin := filepath.Join(t.TempDir(), "xpfd-proto")
	writeFakeVersionBin(t, bin, "ha-protocol-version=3\nha-protocol-min-compat=1\nsession-sync-protocol-version=2\n", 0)
	iv, err := s.ProtocolVersions(bin)
	if err != nil {
		t.Fatalf("ProtocolVersions: %v", err)
	}
	if iv.HAProtocol != 3 || iv.HAProtocolMinCompat != 1 || iv.SessionSyncProtocol != 2 {
		t.Fatalf("ProtocolVersions = %+v, want HA 3 floor 1 sync 2", iv)
	}
	for _, tc := range []struct {
		name, out string
		code      int
	}{
		{"missing sync", "ha-protocol-version=3\nha-protocol-min-compat=1\n", 0},
		{"garbage sync", "ha-protocol-version=3\nha-protocol-min-compat=1\nsession-sync-protocol-version=banana\n", 0},
		{"exec failure", "boom\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := filepath.Join(t.TempDir(), "xpfd-proto")
			writeFakeVersionBin(t, b, tc.out, tc.code)
			if _, err := s.ProtocolVersions(b); err == nil {
				t.Fatal("ProtocolVersions succeeded on a malformed probe; want fail-closed error")
			}
		})
	}
}

func TestUnitExecStartReadsLoadedSystemdProperty(t *testing.T) {
	dir := t.TempDir()
	out := "{ path=/var/lib/xpf/versions/2.0.0/xpfd ; argv[]=/var/lib/xpf/versions/2.0.0/xpfd ; ignore_errors=no }\n"
	writeFakeVersionBin(t, filepath.Join(dir, "systemctl"), out, 0)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	s := &realSystem{unit: "xpfd"}
	got, err := s.UnitExecStart("xpfd")
	if err != nil {
		t.Fatalf("UnitExecStart: %v", err)
	}
	if got != strings.TrimSpace(out) {
		t.Fatalf("UnitExecStart = %q, want %q", got, strings.TrimSpace(out))
	}
}

func TestRunningUnitExeAcceptsInactiveUnit(t *testing.T) {
	dir := t.TempDir()
	writeFakeVersionBin(t, filepath.Join(dir, "systemctl"), "0\n", 0)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	s := &realSystem{unit: "xpfd"}
	got, err := s.RunningUnitExe("xpfd")
	if err != nil {
		t.Fatalf("RunningUnitExe: %v", err)
	}
	if got != "" {
		t.Fatalf("RunningUnitExe = %q, want empty for MainPID 0", got)
	}
}

func TestRunningUnitExeResolvesNonzeroMainPID12174(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"[ \"$#\" -eq 4 ] && [ \"$1\" = \"show\" ] && " +
		"[ \"$2\" = \"--property=MainPID\" ] && [ \"$3\" = \"--value\" ] && " +
		"[ \"$4\" = \"xpfd.service\" ] || exit 64\n" +
		"printf '%s\\n' \"$XPFD_TEST_PID\"\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("XPFD_TEST_PID", itoa(os.Getpid()))

	s := &realSystem{unit: "xpfd"}
	got, err := s.RunningUnitExe("xpfd")
	if err != nil {
		t.Fatalf("RunningUnitExe: %v", err)
	}
	want, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatalf("read /proc/self/exe: %v", err)
	}
	if got != want {
		t.Fatalf("RunningUnitExe = %q, want /proc/self/exe %q", got, want)
	}
}

func TestRealSystemUnitQueriesUseExactSystemctlArgs12174(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"case \"$1|$2|$3|$4\" in\n" +
		"  'show|--property=ExecStart|--value|xpfd.service') printf '%s\\n' \"$XPFD_TEST_EXEC_START\" ;;\n" +
		"  'show|--property=MainPID|--value|xpfd.service') printf '0\\n' ;;\n" +
		"  *) printf 'unexpected systemctl arguments: %s\\n' \"$*\" >&2; exit 64 ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	const execStart = "{ path=/var/lib/xpf/versions/2.0.0/xpfd ; argv[]=/var/lib/xpf/versions/2.0.0/xpfd ; ignore_errors=no }"
	t.Setenv("XPFD_TEST_EXEC_START", execStart)

	s := &realSystem{unit: "xpfd"}
	got, err := s.UnitExecStart("xpfd")
	if err != nil {
		t.Fatalf("UnitExecStart with exact systemctl arguments: %v", err)
	}
	if got != execStart {
		t.Fatalf("UnitExecStart = %q, want %q", got, execStart)
	}
	gotExe, err := s.RunningUnitExe("xpfd")
	if err != nil {
		t.Fatalf("RunningUnitExe with exact systemctl arguments: %v", err)
	}
	if gotExe != "" {
		t.Fatalf("RunningUnitExe = %q, want empty for MainPID 0", gotExe)
	}
}
