package upgrade

import (
	"fmt"
	"strings"
)

// ValidateVersionSegment rejects any version string that is not a safe
// single path segment (plan §4/§6 C1, #1964/#1967). The version keys the
// on-disk runtime layout: versions/<ver>/, the `current` symlink target,
// the per-version DB-snapshot dotfile (.<ver>.dbsnap), and — the strictest
// sink — the systemd unit drop-in's ExecStart path
// (flip.go:writeUnitDropin templates `ExecStart=<VersionsDir>/<ver>/xpfd`).
// A version carrying a path separator, "..", whitespace, a control char, or
// a leading dot would let an attacker (or a corrupted/format-drifted `xpfd
// version` output) escape VersionsDir, collide with a dotfile namespace, or
// strand the daemon on a path that cannot be resolved.
//
// SINK-AWARE ALLOWLIST (#5713 M41): the validator is a strict allowlist —
// [A-Za-z0-9] plus `. _ + ~ - :` — NOT a "reject the obviously bad" filter.
// Debian/semver versions legitimately carry exactly those (`1:2.3.4-1`
// epoch, `1.0.0~beta1`, `1.0.0+build.7`), so nothing legitimate is rejected.
// The allowlist matters because the ExecStart sink re-interprets several
// ASCII-printable characters that are harmless as a bare filesystem path
// segment but DANGEROUS in a systemd unit line:
//   - '%' is a systemd UNIT SPECIFIER (`%i`, `%n`, `%h`, `%%` …): a version
//     like `%i` or `1.0%n` PASSED the old "path segment" filter, landed in
//     ExecStart, and systemd EXPANDED it — silently rewriting argv[0] to an
//     unintended binary after the upgrade STOP. This was M41.
//   - '$' triggers systemd environment-variable expansion.
//   - '"', '\”, '\\', and backtick are consumed by systemd's argv
//     quote/escape splitting and can alter the resolved executable path.
//
// None of these is legal in a Debian/semver version, so the allowlist
// rejects them fail-closed rather than substituting them into ExecStart.
//
// Rejected (with a precise message for the common classes):
//   - empty
//   - "." or ".." (and any leading dot — collides with the .partial /
//     .dbsnap dotfile namespace and is hidden from ReadDir-based GC)
//   - any "/" (path traversal / escape from VersionsDir)
//   - any whitespace (space, tab, newline, CR, vertical tab, form feed)
//   - any ASCII control char (< 0x20) or DEL (0x7f)
//   - any non-ASCII byte (>= 0x80). Debian/semver versions are ASCII; this
//     keeps EXACT parity with the preinst's shell is_safe_segment, which now
//     strips the same allowlist charset (`tr -d 'A-Za-z0-9.:+~_-'`) under the
//     C locale. Keeping the two validators identical avoids a host where the
//     Go seed accepts a version the shell migration would reject (or vice
//     versa).
//   - any other character outside the [A-Za-z0-9._+~:-] allowlist (the
//     systemd-metacharacter class above).
//
// Per-sink divergence from the Python filename sink
// (scripts/dist/sign.py:validate_version, #16190): this ExecStart sink
// allows the epoch ':' and leading '-+_~:' (allowlist-only, no first-char
// rule); the filename sink requires an initial alphanumeric and drops ':'.
// Both outcomes are pinned per sink in
// scripts/dist/version_fixture_16190.json — do not normalise either policy.
func ValidateVersionSegment(ver string) error {
	if ver == "" {
		return fmt.Errorf("version is empty")
	}
	if ver == "." || ver == ".." {
		return fmt.Errorf("version %q is a relative path element", ver)
	}
	if strings.HasPrefix(ver, ".") {
		return fmt.Errorf("version %q has a leading dot (collides with the "+
			"runtime dotfile namespace and is hidden from GC)", ver)
	}
	if strings.ContainsRune(ver, '/') {
		return fmt.Errorf("version %q contains a path separator", ver)
	}
	for _, r := range ver {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			// allowlisted alphanumeric
		case r == '.' || r == '_' || r == '+' || r == '~' || r == '-' || r == ':':
			// allowlisted Debian/semver punctuation
		case r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f':
			return fmt.Errorf("version %q contains whitespace", ver)
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("version %q contains a control character (0x%02x)", ver, r)
		case r >= 0x80:
			return fmt.Errorf("version %q contains a non-ASCII character (%q); "+
				"Debian/semver versions are ASCII", ver, r)
		default:
			// Any other printable ASCII — notably '%' (systemd unit
			// specifier), '$', '"', '\'', '\\', backtick — is rejected
			// fail-closed: it is not a legal Debian/semver version character
			// and would be re-interpreted in the pinned ExecStart path
			// (#5713 M41).
			return fmt.Errorf("version %q contains %q, which is not a safe "+
				"version character (allowed: A-Za-z0-9 . _ + ~ - :); in "+
				"particular '%%' is a systemd unit specifier that would rewrite "+
				"the pinned ExecStart path (#5713 M41)", ver, r)
		}
	}
	return nil
}

// ValidateKernelSegment rejects any kernel version / `uname -r` string that is
// not a safe segment for the kernel A/B channel's filesystem and GRUB uses
// (#5452). It is STRICTER than ValidateVersionSegment because the kernel path
// consumes the string in two additional injection-prone contexts that the
// binary-cut path does not:
//
//   - a glob + delete: filepath.Glob(rooted("/boot/*-"+ver)) feeds every match
//     to os.RemoveAll, and os.RemoveAll(rooted("/lib/modules/"+ver)) deletes a
//     module tree. A glob metacharacter (`*`, `?`, `[`, `]`) in ver widens the
//     pattern — candidateVersion="*" globs "/boot/*-*", matching EVERY dashed
//     /boot file, so RemoveAll wipes all kernels/initrds/config and bricks the
//     host. It also feeds `apt-get purge linux-image-<ver>`, where "*" purges
//     every kernel package. And ".." (even with no "/") traverses:
//     filepath.Join("/lib/modules", "..") == "/lib".
//   - a generated GRUB script: WriteSlotSelector Sprintf's ver into a
//     double-quoted directive `set xpf_slot_kernel="vmlinuz-<ver>"`. A `"`,
//     backslash, or newline injects arbitrary GRUB commands and breaks the
//     boot selector.
//
// ValidateVersionSegment permits `:` (the Debian epoch separator, legal in a
// package version and harmless in the binary-cut path), which the kernel path
// must NOT allow, so it is not sufficient here. (Since #5713 ValidateVersion
// Segment is itself a strict allowlist and no longer permits `*`, `?`, `[`,
// `]`, `"`, `\`; this validator differs only by additionally disallowing `:`.)
// A real `uname -r` is alphanumerics plus `.`, `-`, `+`, `~`, `_` (e.g.
// "6.18.0-xpf1-amd64"), so this validator allows ONLY that charset, is
// non-empty, rejects a leading `-` (would parse as an apt/efi
// option) and any "." / ".." relative element (traversal — a lone "." is in
// the charset but resolves to the parent dir under filepath.Join), and fails
// CLOSED on anything else.
func ValidateKernelSegment(what, seg string) error {
	if seg == "" {
		return fmt.Errorf("%s is empty", what)
	}
	if strings.HasPrefix(seg, "-") {
		return fmt.Errorf("%s %q has a leading '-' (parses as a command option)", what, seg)
	}
	if seg == "." || strings.Contains(seg, "..") {
		// A lone "." is in the charset but resolves to the parent dir under
		// filepath.Join (filepath.Join("/lib/modules", ".") == "/lib/modules"),
		// so a candidateVersion="." would RemoveAll the entire modules tree —
		// same class as "..". Reject both, matching ValidateVersionSegment.
		return fmt.Errorf("%s %q is a relative path element (\".\" / \"..\")", what, seg)
	}
	for _, r := range seg {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '+' || r == '~' || r == '-':
		default:
			return fmt.Errorf("%s %q contains an invalid character %q "+
				"(allowed: A-Za-z0-9 . _ + ~ -)", what, seg, r)
		}
	}
	return nil
}
