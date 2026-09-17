package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// validateLoginClassRef accepts a `system login user <n> class <c>` value that
// is EITHER a system-defined built-in class (super-user/operator/read-only/
// config-viewer/unauthorized, from LoginClassPermissions) OR a custom `system
// login class <c>` defined in the same candidate tree (#4304 S-2). It replaces
// the fixed enum so a valid vSRX RBAC config that defines its own class is no
// longer hard-rejected at commit, while an undefined class still fails closed.
func validateLoginClassRef(raw string, refs *schemaRefs) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected a login class name)")
	}
	if _, ok := LoginClassPermissions[raw]; ok {
		return nil
	}
	if refs != nil {
		if _, ok := refs.loginClasses[raw]; ok {
			return nil
		}
	}
	return fmt.Errorf("login class %q is not defined; use a system-defined class (one of: %s) or add `set system login class %s permissions <...>` in the same commit",
		raw, strings.Join(ValidLoginClasses(), ", "), raw)
}

// cryptModularIDs is the set of crypt(3) modular-hash identifiers xpf
// accepts in an encrypted-password value. It is a permissive superset of
// what Debian 13 glibc / libxcrypt actually verify against — the OS, not
// this validator, is the final authority at PAM time, so we err toward
// "clearly a hash" rather than a brittle per-id structural parse. yescrypt
// ($y$) is the Debian 13 default; $6$ (sha512crypt) is universal; $2a$/
// $2b$/$2y$ (bcrypt), $5$ (sha256crypt), $1$ (md5crypt), $7$ (scrypt) and
// $gy$ (gost-yescrypt) are present via libxcrypt. #1944 §5.5.
var cryptModularIDs = map[string]bool{
	"1": true, "2a": true, "2b": true, "2y": true,
	"5": true, "6": true, "7": true, "y": true, "gy": true,
}

// cryptFieldRune reports whether r is allowed inside a crypt(3) salt or
// checksum field. The crypt-base64 alphabet is [./0-9A-Za-z]; modular
// param fields (e.g. yescrypt $y$j9T$... or sha512crypt
// $6$rounds=656000$...) additionally use '=' to introduce a parameter
// value. We allow '=' here and reject ':' implicitly (not in the set) so
// a value can never corrupt the `user:hash` chpasswd stdin line.
func cryptFieldRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '.' || r == '/' || r == '=':
		return true
	}
	return false
}

// ValidateCryptHash accepts a crypt(3) modular password hash or an
// explicit lock sentinel, and HARD-REJECTS plaintext. It is shared by
// `system root-authentication encrypted-password` and `system login user
// <name> authentication encrypted-password` (#1944, E1).
//
// Accepted:
//   - A modular crypt hash: an optional leading "!" or "!!" (the
//     locked-but-restorable form), then $<id>$<salt>$<checksum> where
//     <id> ∈ cryptModularIDs, <salt> is non-empty (and may itself carry
//     $-separated params such as rounds=N), and the FINAL $-field (the
//     checksum) is non-empty. A trailing empty checksum ($6$salt$) is
//     rejected — it writes a malformed shadow field PAM refuses.
//   - A bare lock sentinel: "*", "!", or "!!". This is the intentional
//     Unix way to lock an account and the only way to lock root via
//     config (root is excluded from the per-user D2 auto-lock). Accepting
//     a deliberate sentinel is NOT the plaintext footgun.
//
// Rejected: plaintext (no leading $-id, not a sentinel — the real
// footgun), the empty string, an unknown $<id>$, an empty salt or empty
// checksum, and any value carrying ':' (would corrupt chpasswd stdin) or
// a control character. Legacy 13-char DES is deliberately NOT accepted so
// that "reject plaintext" is an absolute guarantee (a 13-char alnum
// password would otherwise pass).
func ValidateCryptHash(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing value (expected a crypt(3) hash, e.g. from `openssl passwd -6`)")
	}
	// Bare lock sentinels — deliberate, accepted as-is.
	if raw == "*" || raw == "!" || raw == "!!" {
		return nil
	}
	// Modular crypt hash, with an optional locked-but-restorable prefix.
	body := raw
	if strings.HasPrefix(body, "!!") {
		body = body[2:]
	} else if strings.HasPrefix(body, "!") {
		body = body[1:]
	}
	if !strings.HasPrefix(body, "$") {
		return fmt.Errorf("not an encrypted password hash (got %q) — plaintext is not "+
			"allowed; generate a hash with `openssl passwd -6` or `mkpasswd -m sha512crypt`", raw)
	}
	// Split into $-separated fields: leading "$" yields an empty first
	// element, so fields[0]=="" , fields[1]=<id>, fields[2..]=salt/params,
	// fields[last]=checksum. Require at least id + salt + checksum.
	fields := strings.Split(body, "$")
	// fields[0] is the empty string before the first '$'.
	if len(fields) < 4 {
		return fmt.Errorf("malformed crypt hash %q — expected $<id>$<salt>$<checksum>", raw)
	}
	id := fields[1]
	if !cryptModularIDs[id] {
		return fmt.Errorf("unknown crypt hash id %q in %q — expected one of "+
			"1, 2a, 2b, 2y, 5, 6, 7, y, gy", id, raw)
	}
	salt := fields[2]
	checksum := fields[len(fields)-1]
	if salt == "" {
		return fmt.Errorf("empty salt in crypt hash %q", raw)
	}
	if checksum == "" {
		return fmt.Errorf("empty checksum in crypt hash %q — a trailing $ "+
			"with no checksum writes a malformed shadow field", raw)
	}
	// Every salt/param/checksum field must be NON-EMPTY and use only the
	// crypt alphabet (which excludes ':' and whitespace), so the value can
	// never corrupt the chpasswd `user:hash` stdin line or smuggle a
	// separator. An empty intermediate field (e.g. "$6$salt$$hash", a
	// doubled '$') is not a valid modular crypt hash — it would pass an
	// alphabet-only check (no chars to reject) but fail at PAM, locking the
	// operator out. Reject it at commit (Copilot #1944 review).
	for _, f := range fields[2:] {
		if f == "" {
			return fmt.Errorf("empty field in crypt hash %q — a doubled "+
				"'$' (e.g. $6$salt$$hash) is malformed", raw)
		}
		for _, r := range f {
			if !cryptFieldRune(r) {
				return fmt.Errorf("invalid character %q in crypt hash %q", r, raw)
			}
		}
	}
	return nil
}

// MaxRingEntries is the inclusive upper bound for the AF_XDP `ring-entries`
// per-queue knob (#2524). The Rust helper preallocates UMEM frames directly
// from this value: per bind.rs binding_frame_count_for_driver, a virtio_net
// binding reserves ~3×ring_entries frames at UMEM_FRAME_SIZE=4096, i.e.
// ~96 MB per binding at ring_entries=8192 (×queues ×interfaces). With no
// ceiling a fat-fingered or malicious value drove an enormous preallocation
// and OOM'd at bring-up instead of failing as a clean commit/startup error.
// 16384 is double the documented 8192 example (~192 MB/binding worst case)
// and is the largest value we consider sane on a router; it must agree with
// the Rust backstop (afxdp/coordinator/reconcile/bringup.rs clamps to the
// same ceiling). The value must additionally be a power of two — the helper
// rounds ring sizes up to a power of two (xsk_ffi.rs next_power_of_two), so
// requiring it at commit keeps the configured number honest about the size
// actually allocated.
const MaxRingEntries = int64(16384)

// ValidateRingEntries accepts a bare integer in [1, MaxRingEntries] that is
// also a power of two. It is the typed-leaf gate for `system dataplane
// ring-entries` (#2524). Before #2524 the leaf used ValidateIntegerMin(1):
// any large value committed and was passed to the dataplane, where it sized
// per-binding UMEM preallocations and could OOM at bring-up. The power-of-two
// requirement matches the helper's own rounding so the operator-visible
// number equals the allocated ring depth.
func ValidateRingEntries(raw string, _ *Config) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected integer)")
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("not an integer: %q", raw)
	}
	if v < 1 || v > MaxRingEntries {
		return fmt.Errorf("ring-entries out of range [1..%d] (got %d)", MaxRingEntries, v)
	}
	if v&(v-1) != 0 {
		return fmt.Errorf("ring-entries must be a power of two in [1..%d] (got %d)", MaxRingEntries, v)
	}
	return nil
}

// #4902: several untyped `system` string leaves are rendered VERBATIM into
// root-owned host service / resolver config files that are then reloaded:
//
//   - `system ntp server <s>`                  -> chrony sources
//   - `system domain-name`/`domain-search`     -> Domains=/search (resolved/resolv.conf)
//   - `system services ssh key-exchange|ciphers|macs` -> sshd drop-in
//   - `system syslog file <name>`/`user <user>`-> /etc/rsyslog.d drop-in + filename
//
// The lexer decodes `\n` inside a quoted string into a literal newline, so a
// crafted value could inject an additional directive line or make a reload
// fail. The global control-char gate (freetext.go: validateNodesControlChars
// strict-rejects, SanitizeTreeControlChars scrubs on lenient load) closes the
// NEWLINE vector, but a value that is control-char-clean yet still outside the
// token's grammar — an embedded SPACE (a second directive token), a path
// separator in a syslog filename, or a malformed value — is not caught by that
// generic gate. It commits, reaches the root-owned config, and either injects
// an extra token or persistently fails the service reload (read as ordinary
// apply degradation). These typed validators constrain each rendered token to
// its real grammar, strict at commit-check (SchemaValidate). The tolerant load
// / peer-sync path keeps booting (#1960); the render-side belts (pkg/daemon
// renderChronySources / buildSSHDConfig / applySyslogFiles / mergeDNSInput)
// re-apply the same checks so a leniently-loaded bad value never reaches the
// generated file.

// sshAlgorithmRE is the safe OpenSSH algorithm-token shape for a single
// KexAlgorithms / Ciphers / MACs entry. OpenSSH algorithm names are letters,
// digits, and the punctuation `- _ . @ +` (e.g. curve25519-sha256@libssh.org,
// diffie-hellman-group-exchange-sha256, hmac-sha2-256-etm@openssh.com,
// aes256-gcm@openssh.com). It deliberately excludes whitespace, control
// characters, and the comma that joins the list — a token carrying a comma or
// space would smuggle a second sshd directive token onto the rendered line (or
// fail the sshd reload).
var sshAlgorithmRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]*$`)

// syslogNameRE is the safe shape for a `system syslog file <name>` filename or
// a `system syslog user <user>` account token. The name is formatted into a
// file path (/var/log/<name>, /etc/rsyslog.d/10-xpf-<name>.conf) and into the
// rsyslog drop-in body, so it must not contain a path separator, whitespace,
// control characters, or rsyslog metacharacters. A leading alnum plus
// [A-Za-z0-9._-] covers real log/account names while excluding `/`, spaces, and
// directive punctuation.
var syslogNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// validateDNSNameShape checks that name is a syntactically valid DNS name: LDH
// labels (letters, digits, hyphens; no leading/trailing hyphen) joined by dots,
// an optional single trailing dot, within the RFC length caps. `what` names the
// leaf for the error. A control-char or space value fails here (space is
// non-LDH), so a domain/hostname value cannot inject a second config token.
func validateDNSNameShape(name, what string) error {
	stripped := strings.TrimSuffix(name, ".")
	if stripped == "" {
		return fmt.Errorf("%s %q has no labels", what, name)
	}
	if len(stripped) > maxDNSNameLen {
		return fmt.Errorf("%s %q exceeds %d octets", what, name, maxDNSNameLen)
	}
	for _, lbl := range strings.Split(stripped, ".") {
		if lbl == "" {
			return fmt.Errorf("%s %q has an empty label (leading/trailing/doubled dot)", what, name)
		}
		if len(lbl) > maxDNSLabelLen {
			return fmt.Errorf("%s label %q exceeds %d octets", what, lbl, maxDNSLabelLen)
		}
		if lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return fmt.Errorf("%s label %q begins or ends with '-'", what, lbl)
		}
		for _, r := range lbl {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
				r >= '0' && r <= '9', r == '-':
				// LDH.
			default:
				return fmt.Errorf("%s %q contains the non-LDH character %q "+
					"(only letters, digits, hyphens, and dots are allowed)", what, name, r)
			}
		}
	}
	return nil
}

// ValidateNTPServer accepts a `system ntp server` value that is either a bare
// IP address (chrony `server`/`pool` target) or a DNS hostname. It rejects an
// embedded space (a second chrony directive token such as `trust`/`prefer`), a
// control character, or a malformed value — any of which would inject an extra
// token into the rendered chrony source line or fail the chrony reload (#4902).
func ValidateNTPServer(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing NTP server (expected an IP address or hostname)")
	}
	if net.ParseIP(raw) != nil {
		return nil
	}
	return validateDNSNameShape(raw, "ntp server")
}

// ValidateSyslogHost accepts a `security log stream <s> host` /
// `system syslog host <h>` value: an IP address or a DNS hostname.
//
// #9326: this leaf was UNTYPED (`args: 1`, no valueType, no validator), so any
// string an operator typed reached `net.Dial`'s resolver on the commit path —
// including one that is not a hostname at all. The dial is now deferred for
// TCP/TLS and bounded for UDP, so this is no longer the only thing standing
// between a typo and a stalled commit; it is the half that gives the operator
// the error at the point they can act on it, naming the leaf, instead of a
// resolver failure logged later from a background warm.
//
// Same admission shape as ValidateNTPServer, which is the closest sibling: both
// are "an address or a name" leaves that end up in a dialer. The noun differs so
// the message names the leaf the operator actually typed.
func ValidateSyslogHost(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing syslog host (expected an IP address or hostname)")
	}
	if net.ParseIP(raw) != nil {
		return nil
	}
	return validateDNSNameShape(raw, "syslog host")
}

// ValidateDNSDomain accepts a `system domain-name` / `system domain-search`
// value: a DNS domain name (LDH labels, optional trailing dot). An empty value
// is accepted (the compiler/renderer skips it); a space/control/malformed value
// is rejected so it cannot inject an extra token into the resolved.conf
// `Domains=` line or the resolv.conf `search` line (#4902).
func ValidateDNSDomain(raw string, _ *Config) error {
	if raw == "" {
		return nil
	}
	return validateDNSNameShape(raw, "domain")
}

// ValidateSystemHostname accepts the `system host-name` value. Unlike the
// resolver/domain leaves, this name becomes the kernel node identity and is
// persisted verbatim, so its admission diagnostic names `host-name` directly.
// Empty is the unset form and remains valid: compileSystem leaves it empty and
// applyHostname's empty early-return is load-bearing for config loads that do
// not configure a system name.
func ValidateSystemHostname(raw string, _ *Config) error {
	if raw == "" {
		return nil
	}
	if err := validateDNSNameShape(raw, "system host-name"); err != nil {
		return err
	}
	// Linux sethostname(2) rejects names longer than HOST_NAME_MAX (64
	// bytes), even though DNS permits up to 253 octets. Keep admission aligned
	// with the syscall that applyHostname ultimately invokes.
	if len(raw) > maxSystemHostnameLen {
		return fmt.Errorf("system host-name %q exceeds Linux HOST_NAME_MAX of %d bytes",
			raw, maxSystemHostnameLen)
	}
	return nil
}

const maxSystemHostnameLen = 64

// ValidateSSHAlgorithm accepts one `system services ssh key-exchange | ciphers
// | macs` token: a safe OpenSSH algorithm name (sshAlgorithmRE). It rejects a
// comma (the list separator), whitespace, control characters, or any other
// metacharacter so a crafted token cannot smuggle a second sshd directive token
// onto the rendered KexAlgorithms/Ciphers/MACs line or fail the sshd reload
// (#4902).
func ValidateSSHAlgorithm(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing SSH algorithm name")
	}
	if !sshAlgorithmRE.MatchString(raw) {
		return fmt.Errorf("invalid SSH algorithm %q (must match %s: a letter or digit "+
			"followed by letters, digits, or the punctuation . _ @ + - ; no whitespace, "+
			"commas, or control characters)", raw, sshAlgorithmRE.String())
	}
	return nil
}

// ValidateSyslogFileName accepts a `system syslog file <name>` destination
// name. The name is formatted into a file path (/var/log/<name>) and a drop-in
// filename (/etc/rsyslog.d/10-xpf-<name>.conf), so it must be a safe base name
// with no path separator, no `..`, no whitespace, and no rsyslog
// metacharacters (#4902).
func ValidateSyslogFileName(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing syslog file name")
	}
	if strings.Contains(raw, "..") || !syslogNameRE.MatchString(raw) {
		return fmt.Errorf("invalid syslog file name %q (must match %s: a letter or digit "+
			"followed by letters, digits, or . _ - ; no '/', '..', whitespace, or control "+
			"characters — it is written to /var/log/<name>)", raw, syslogNameRE.String())
	}
	return nil
}

// ValidateSyslogUser accepts a `system syslog user <user>` destination: either
// the wildcard `*` (all logged-in users) or a safe account name (syslogNameRE).
// The value is formatted into a drop-in filename and the rsyslog
// `:omusrmsg:<user>` directive, so a path separator, whitespace, or control
// character is rejected (#4902).
func ValidateSyslogUser(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing syslog user")
	}
	if raw == "*" {
		return nil
	}
	if strings.Contains(raw, "..") || !syslogNameRE.MatchString(raw) {
		return fmt.Errorf("invalid syslog user %q (must be '*' or match %s: a letter or "+
			"digit followed by letters, digits, or . _ - ; no '/', whitespace, or control "+
			"characters)", raw, syslogNameRE.String())
	}
	return nil
}

// SyslogSelectorAtomSafe reports whether one atom of an rsyslog selector token
// can be interpolated without escaping it.
//
// This is the SINGLE SOURCE of that rule. pkg/daemon's render belt (#5797/#6829)
// delegates to it, and the #6844 commit-time facility gate uses it, so what the
// commit path ACCEPTS and what the render path WRITES cannot diverge.
//
// The direction is forced: pkg/daemon imports pkg/config, so the rule has to
// live here for the render belt to reach it. Two copies would drift, and the
// drift has a name -- a config that commits cleanly and whose destination then
// silently disappears at render, which is the exact failure class #6844 exists
// to close. A gate that admits bytes the renderer rejects has not closed it.
//
// LOAD-BEARING: the ordinary SPACE is the byte this exists for, not the control
// characters it superficially resembles a check for. A newline cannot reach here
// (the lexer folds it to a space), while a space alone separates an rsyslog
// selector from its ACTION field, so a token containing one can push text into
// the action position of a managed line. Relaxing this to "printable ASCII" or
// "no control bytes" would keep rejecting the newline and start admitting the
// space: the guard would look intact and stop guarding anything.
//
// #6829 B1: the hyphen is legal INSIDE an atom and never at its head. A leading
// `-` is a legacy sysklogd/rsyslog HOSTNAME-FILTER directive, which scopes every
// selector that follows it -- so the byte does not merely appear in the line, it
// changes what the following lines MEAN. Internal hyphens stay legal;
// `interactive-commands` is a real Junos facility and a real rendered selector.
func SyslogSelectorAtomSafe(atom string) bool {
	if atom == "" {
		return false
	}
	if c := atom[0]; !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
		return false
	}
	for i := 0; i < len(atom); i++ {
		c := atom[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}

// SyslogSelectorFacilitySafe reports whether a facility token can be
// interpolated into the FACILITY position of an rsyslog selector.
//
// The rule is position-aware because rsyslog's selector grammar is
// `<facility>.<priority>`, where `*` stands for all facilities and the comma
// operator specifies several facilities with one priority pattern. Both are
// NATIVE syntax in this position, both commit on this box today, and both are
// asserted to render (`auth,authpriv.info`, `*.info`).
//
// Rejecting them would not be conservative, it would be a silent regression:
// a strict-commit-clean, rsyslog-valid destination would be warned about and
// reconciled AWAY on upgrade.
//
// Admitting them costs nothing, because neither can carry a payload. `*` is
// accepted only as the WHOLE token, and one byte rendered as `%s.%s` can only
// produce `*.<severity>`. A comma list is accepted only when EVERY member is a
// nonempty safe atom, so `auth,authpriv` renders while `auth,`, `,auth` and
// `auth,,authpriv` are rejected -- an empty member is malformed rsyslog, and
// accepting it would let the size of the accepted set stop being a function of
// the bytes in it.
//
// Everything rejected for structural reasons -- `;`, `.`, `:`, `_`, whitespace,
// control bytes, arbitrary punctuation -- is still rejected in every position.
// `daemon;*.* /tmp/pwn` is still dropped.
//
// Empty is SAFE here: the render call sites fold an empty facility to the `*`
// wildcard before building the selector, so an unset facility is ordinary
// configuration rather than an omission to reject. The commit-time gate applies
// its own non-empty check, because a schema KEY always has a token.
func SyslogSelectorFacilitySafe(tok string) bool {
	if tok == "" || tok == "*" {
		return true
	}
	for _, atom := range strings.Split(tok, ",") {
		if !SyslogSelectorAtomSafe(atom) {
			return false
		}
	}
	return true
}

// maxSyslogFacilityLen bounds the facility name. The longest real one,
// `interactive-commands`, is 20 characters; 64 leaves generous headroom while
// keeping an absurd value out of a rendered selector line.
const maxSyslogFacilityLen = 64

// ValidateSyslogFacility gates the `system syslog <dest> <facility> <severity>`
// facility KEY.
//
// The severity half of that pair has been enum-gated since #2008; the facility
// half was an unvalidated wildcard key, so `set system syslog file audit
// "daemon;*.* /tmp/pwn" info` passed SchemaValidate and landed in
// SyslogFileConfig.Facility verbatim (#6844). #6829 belted the render site, so
// nothing injected reaches rendered rsyslog configuration; this is the other
// half -- the commit path told the operator nothing, and their configuration
// silently did not do what it said.
//
// It delegates to SyslogSelectorFacilitySafe, the same predicate the render
// belt uses, RATHER than carrying its own alphabet. A first cut did carry one,
// and it was wrong in both directions: it rejected `auth,authpriv` and bare `*`
// (documented, supported, render-tested forms, so valid configs would have
// stopped committing) while admitting `.` and `_`, which the renderer drops --
// leaving the "commit succeeds, destination disappears" class the gate was
// written to close still open. Sharing the predicate makes commit-accepts and
// render-writes the same set by construction.
//
// It is NOT an enum of Junos facility names. That vocabulary already exists in
// pkg/logging, which imports pkg/config, so the two cannot be single-sourced
// without a new leaf package; two copies drift, and the drift is silent in the
// direction that REJECTS a valid operator config the renderer maps correctly.
// #6830 diagnoses an unmapped facility at render, by name.
//
// Strictness is bounded by the existing #1319 split rather than by a new lenient
// opt: SchemaValidate is strict only on the operator-driven commit /
// commit-check path, and Store.compileTreeLenient downgrades a violation to a
// warning on the tolerant Load / SyncApply ingress. So a persisted or
// peer-synced config carrying a name this rejects still BOOTS, per #1960.
func ValidateSyslogFacility(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing syslog facility")
	}
	if len(raw) > maxSyslogFacilityLen {
		return fmt.Errorf("syslog facility %q is %d characters (max %d)",
			raw, len(raw), maxSyslogFacilityLen)
	}
	if !SyslogSelectorFacilitySafe(raw) {
		return fmt.Errorf("invalid syslog facility %q: a facility is `*`, or a "+
			"comma-separated list of names each starting with a letter or digit and "+
			"containing only letters, digits and internal hyphens. No whitespace, "+
			"control characters, or rsyslog selector punctuation such as ';' '.' ':' "+
			"'_'. Junos facility names are %s, or a BSD name / local0-local7",
			raw, junosSyslogFacilityList())
	}
	return nil
}

// junosSyslogFacilityNames is the `[edit system syslog]` facility vocabulary
// this box advertises to an operator in a commit error.
//
// IT IS A CLAIM, NOT A DECORATION. An operator reads this list, writes one of
// the names, and expects records under it. A name that appears here but is not
// mapped commits, files silently to local0, and emits nothing under the name
// the operator asked for -- which is exactly the failure the list exists to
// prevent.
//
// Two names were removed in #7187 because they were never `[edit system
// syslog]` facilities, and the repository had ALREADY established that in
// pkg/logging (parse_facility_checked_5797_test.go, verified against the
// documentation) while this message went on advertising them:
//
//   - `security` names a DIFFERENT hierarchy, `[edit security log]`.
//   - `ntp` is excluded by the empty-second-column rule: Table 2 carries the
//     NTP code with no Junos facility name against it, and such a code "cannot
//     be included in a statement at the [edit system syslog] hierarchy level".
//     junosRemoteFacility documents this at length and deliberately omits it.
//
// The two are kept honest by TestConfigFacilityAdviceMatchesTheWireMapping7187
// in pkg/logging, which asserts this list and the wire mapping agree in BOTH
// directions. The agreement is asserted rather than one side pinned to a
// literal, because a literal encodes which side you trust -- and here the side
// everyone trusted (this message) was the wrong one.
//
// `any` is deliberately present and is deliberately the ONE exception to the
// mapping agreement: it is a selector wildcard valid on the rsyslog-backed
// file/user destinations, not a numeric facility a host client can stamp.
var junosSyslogFacilityNames = []string{
	"any",
	"authorization", "change-log", "conflict-log", "daemon", "dfc",
	"firewall", "ftp", "interactive-commands", "kernel", "pfe", "user",
}

// JunosSyslogFacilityNames returns the advertised `[edit system syslog]`
// facility vocabulary. Exported so pkg/logging can assert it against the wire
// mapping; pkg/logging imports pkg/config, so the dependency cannot run the
// other way and the two lists cannot be single-sourced.
func JunosSyslogFacilityNames() []string {
	return append([]string(nil), junosSyslogFacilityNames...)
}

// junosSyslogFacilityList renders the vocabulary for an operator-facing error.
func junosSyslogFacilityList() string {
	quoted := make([]string, 0, len(junosSyslogFacilityNames))
	for _, n := range junosSyslogFacilityNames {
		quoted = append(quoted, "`"+n+"`")
	}
	return strings.Join(quoted, ", ")
}

// zoneNameSegmentRE is the safe shape for one `/`-separated segment of a
// `system time-zone` value (an IANA tz-database / zoneinfo name). Real zone
// segments are letters, digits, and the punctuation `_ + -`
// (America/Los_Angeles, Etc/GMT+5, Etc/GMT-14, America/Port-au-Prince), each
// beginning with a letter or digit. The alphabet deliberately EXCLUDES '.' (so
// a '.' or '..' path component can never appear), '/' (the segment separator),
// whitespace, and control characters — any of which could turn the rendered
// /etc/localtime symlink target into a path-traversal.
var zoneNameSegmentRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_+-]*$`)

// maxTimeZoneLen bounds a `system time-zone` value. IANA zone names are short
// (the longest shipped name is well under 40 octets); 64 is a comfortable cap
// that still rejects an absurdly long traversal string.
const maxTimeZoneLen = 64

// maxUnixSocketPathLen bounds a helper socket path. AF_UNIX sun_path is a
// 108-byte array that must hold a NUL terminator, so 107 octets is the longest
// path the kernel can bind — a longer one fails at bind() with EINVAL, which
// surfaces as an opaque dataplane bring-up failure rather than a commit error.
const maxUnixSocketPathLen = 107

// ValidateUnixSocketPath accepts a `system dataplane control-socket` value: the
// filesystem path the Rust helper binds its control listener on and the daemon
// dials (pkg/dataplane/userspace/process.go, process_control.go).
//
// It must be an ABSOLUTE, traversal-free path that names a file, because:
//
//   - the daemon and the helper are separate processes, so a relative path is
//     resolved against whatever working directory each happens to hold;
//   - the path is handed to the stale-socket unlink at every bring-up, so a
//     `..` component lets a stored config aim that unlink outside the runtime
//     directory it appears to name (#5839);
//   - a trailing slash or a bare `/` names no socket at all;
//   - a path over sun_path's 107 usable octets can never bind.
//
// Strict at commit-check (SchemaValidate) only. The tolerant load / peer-sync
// path keeps booting on a stale value (#1960 no-brick: pkg/configstore
// compileTreeLenient warns and continues), and the runtime is not relying on
// this gate — removeStaleUnixSocket re-judges the path defensively at every
// bring-up, which is what protects a value that never passed through a strict
// commit at all. Rejecting `.`/`..` here removes the traversal spelling most
// likely to be written by hand; it does NOT make the runtime path
// alias-proof — a symlinked parent still aliases (#7139).
func ValidateUnixSocketPath(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing value (expected an absolute socket path, e.g. /run/xpf/userspace-dp.sock)")
	}
	if !strings.HasPrefix(raw, "/") {
		return fmt.Errorf("socket path %q must be absolute (start with '/'): the daemon and the "+
			"dataplane helper are separate processes and resolve a relative path against "+
			"their own working directories", raw)
	}
	if len(raw) > maxUnixSocketPathLen {
		return fmt.Errorf("socket path %q is %d octets, over the %d-octet AF_UNIX sun_path limit",
			raw, len(raw), maxUnixSocketPathLen)
	}
	if strings.HasSuffix(raw, "/") {
		return fmt.Errorf("socket path %q must name a socket file, not a directory (no trailing '/')", raw)
	}
	for _, seg := range strings.Split(raw, "/")[1:] {
		switch seg {
		case "":
			return fmt.Errorf("socket path %q must not contain an empty component (doubled '/')", raw)
		case ".", "..":
			return fmt.Errorf("socket path %q must not contain a %q component: the path is unlinked "+
				"at every dataplane bring-up and must not be able to leave the directory it names", raw, seg)
		}
		if strings.IndexFunc(seg, func(r rune) bool { return r < 0x20 }) >= 0 {
			return fmt.Errorf("socket path %q must not contain control characters (including NUL)", raw)
		}
	}
	return nil
}

// ValidateTimeZone accepts a `system time-zone` value: an IANA tz-database /
// zoneinfo name such as `UTC`, `America/Los_Angeles`, or `Etc/GMT+5`. The value
// is rendered into the /etc/localtime symlink target
// (/usr/share/zoneinfo/<value>), so it must be a relative, traversal-free
// path: one or more `/`-separated segments, each matching zoneNameSegmentRE. An
// empty value, an absolute path (leading `/`), a `..` component, a trailing /
// doubled slash, or any segment with a space / control character / other
// metacharacter is rejected so the value cannot escape the zoneinfo root
// (#5011).
//
// Strict at commit-check (SchemaValidate); the tolerant load / peer-sync path
// keeps booting (#1960) and the render belt (zoneinfoTarget in
// pkg/daemon/daemon_system.go) refuses an out-of-root symlink target for a
// value that slips through.
func ValidateTimeZone(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing value (expected a time zone, e.g. UTC or America/Los_Angeles)")
	}
	if len(raw) > maxTimeZoneLen {
		return fmt.Errorf("time-zone %q exceeds %d octets", raw, maxTimeZoneLen)
	}
	for _, seg := range strings.Split(raw, "/") {
		if !zoneNameSegmentRE.MatchString(seg) {
			return fmt.Errorf("invalid time-zone %q: segment %q must be a zoneinfo name "+
				"component (a letter or digit followed by letters, digits, or _ + - ; no "+
				"'.', '..', '/', whitespace, or control characters)", raw, seg)
		}
	}
	return nil
}
