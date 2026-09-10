package config

// schema_system.go carries the system-management subtrees of the
// config-mode grammar SSOT (#1891 domain split): `system`, `services`,
// `snmp`, and `event-options`. The root composition, the schemaNode
// type, and the split rationale live in schema.go.

// junosSyslogSeverities is the fixed Junos syslog severity vocabulary used
// for the value slot of a `<facility> <severity>` system-syslog pair. The
// facility keyword itself is open-ended (a wildcard schema child), but the
// severity is one of these names; anything else is a typo the runtime would
// silently treat as "no severity filter" (logging.ParseSeverity returns 0
// for unknown names). All ten names below map to a real MinSeverity threshold
// in logging.ParseSeverity (#5314). #2008.
var junosSyslogSeverities = []string{
	"any", "none", "emergency", "alert", "critical",
	"error", "warning", "notice", "info", "debug",
}

// syslogFacilitySeverityLeaf builds the wildcard typed leaf used for a
// system-syslog `<facility> <severity>` pair. It is a fresh node per call so
// that each destination (host/file/user) owns an independent wildcard and a
// future edit to one does not alias the others. #2008.
func syslogFacilitySeverityLeaf() *schemaNode {
	return &schemaNode{
		desc:          "Syslog facility (value is the severity threshold)",
		args:          1,
		placeholder:   "<severity>",
		valueType:     ValueEnumOf,
		valueDesc:     "syslog severity threshold",
		valueExamples: []string{"any", "info", "warning", "error"},
		validator:     ValidateEnum(junosSyslogSeverities),
		// #6844: the facility NAME is this leaf's wildcard KEY. Without a
		// keyValidator an arbitrary string -- including one carrying ';',
		// whitespace or a newline -- passed SchemaValidate and committed, so
		// the operator got no error and their configuration silently did not
		// do what it said. The severity VALUE above has been enum-gated since
		// #2008; this is the other half of the same pair.
		keyValueType: ValueIdentifier,
		keyValueDesc: "Junos syslog facility name, or 'any' for all facilities",
		keyValidator: ValidateSyslogFacility,
	}
}

// syslogDestinationModifiers builds the named (non-facility) sub-statements a
// system-syslog host/file/user destination accepts. These MUST be modelled as
// named children so they take precedence over the `<facility> <severity>`
// wildcard: without an exact-match entry a `source-address 10.0.1.1` /
// `port 5514` / `match "re"` hits the severity-enum wildcard and the strict
// commit-check REJECTS it (the value is not a Junos severity). `extra` folds
// in per-destination keywords (host: source-address/port; file: archive).
// Fresh maps/nodes per call so destinations never alias (#4303 S-1).
func syslogDestinationModifiers(extra map[string]*schemaNode) map[string]*schemaNode {
	children := map[string]*schemaNode{
		"allow-duplicates":  {desc: "Do not suppress duplicate messages", children: nil},
		"match":             {desc: "Regular-expression message filter", args: 1, placeholder: "<regex>", children: nil},
		"match-strings":     {desc: "Message string filter", args: 1, placeholder: "<string>", children: nil},
		"explicit-priority": {desc: "Include priority in the logged message", children: nil},
		"structured-data": {desc: "Log in RFC 5424 structured-data format", children: map[string]*schemaNode{
			"brief": {desc: "Omit the English-language message text", children: nil},
		}},
	}
	for k, v := range extra {
		children[k] = v
	}
	return children
}

var schemaSystem = &schemaNode{desc: "System configuration", children: map[string]*schemaNode{
	"host-name": {desc: "System hostname", args: 1, scalar: true, placeholder: "<hostname>", children: nil},
	// #4902: domain-name / domain-search are rendered verbatim into the
	// resolved.conf `Domains=` line and the resolv.conf `search` line. Type them
	// as DNS names so a space/control/malformed value cannot inject an extra
	// resolver directive token.
	"domain-name":   {desc: "Domain name", args: 1, valueType: ValueHostname, valueDesc: "DNS domain name", valueExamples: []string{"example.net"}, validator: ValidateDNSDomain, placeholder: "<domain>", children: nil},
	"domain-search": {desc: "Domain search list", args: 1, multi: true, valueType: ValueHostname, valueDesc: "DNS domain name", valueExamples: []string{"example.net", "corp.example.net"}, validator: ValidateDNSDomain, placeholder: "<domain>", children: nil},
	// #5011: time-zone is rendered into the /etc/localtime symlink target
	// (/usr/share/zoneinfo/<value>). Type it as a zoneinfo name so a `..`
	// component / absolute path / space cannot turn the symlink target into a
	// path-traversal. The daemon render belt (zoneinfoTarget) is the second
	// boundary for a leniently-loaded value (#1960).
	"time-zone":    {desc: "System time zone", args: 1, valueType: ValueTimeZone, valueDesc: "IANA time zone name", valueExamples: []string{"UTC", "America/Los_Angeles", "Etc/GMT+5"}, validator: ValidateTimeZone, placeholder: "<timezone>", children: nil},
	"no-redirects": {desc: "Disable ICMP redirects", children: nil},
	// #1319 PR 3: compiled verbatim and written into the resolver
	// drop-in (pkg/daemon/daemon_dns.go:114) — a garbage server
	// string silently produced broken DNS configuration.
	"name-server": {
		desc:          "DNS name server",
		args:          1,
		multi:         true,
		placeholder:   "<address>",
		valueType:     ValueIPAddress,
		valueDesc:     "DNS server IP address (IPv4 or IPv6)",
		valueExamples: []string{"8.8.8.8", "2001:4860:4860::8888"},
		validator:     ValidateIPAddress,
		children:      nil,
	},
	"backup-router": {desc: "Backup router", args: 1, placeholder: "<address>", closedWorld: true, children: map[string]*schemaNode{
		"destination": {desc: "Destination network", args: 1, placeholder: "<network>", children: nil},
	}},
	// packedStatements (issue 8858): SSHKeys is a []string, so a packed
	// `root-authentication ssh-ed25519 <k1> ssh-ed25519 <k2>` run must split
	// into one child per statement or the second key is silently lost. The
	// scope admission alone compiles the FIRST key and looks complete; only a
	// two-key fixture shows the fold. Every child here is a modelled args:1
	// leaf, so the tail splits cleanly.
	"root-authentication": {desc: "Root authentication", packedStatements: true, children: map[string]*schemaNode{
		// #1944 E1: share ValidateCryptHash with per-user
		// authentication so root's identical plaintext footgun is
		// closed (one validator, one error message).
		"encrypted-password": {desc: "Encrypted password", args: 1, placeholder: "<crypt-hash>",
			valueType: ValueCryptHash, validator: ValidateCryptHash, children: nil},
		"ssh-ed25519": {desc: "SSH ED25519 public key", args: 1, multi: true, placeholder: "<key>", children: nil},
		"ssh-rsa":     {desc: "SSH RSA public key", args: 1, multi: true, placeholder: "<key>", children: nil},
		"ssh-dsa":     {desc: "SSH DSA public key", args: 1, multi: true, placeholder: "<key>", children: nil},
	}},
	"archival": {desc: "Configuration archival", children: map[string]*schemaNode{
		"configuration": {desc: "Configuration archival", children: map[string]*schemaNode{
			"transfer-on-commit": {desc: "Transfer on commit", children: nil},
			// #4078: periodic off-box archive every N minutes, independent of
			// transfer-on-commit. Parsed+compiled since the leaf was added, but
			// the runtime periodic timer (reconcileArchiveTimer) that consumes
			// it landed in #4078 — before that this leaf was accepted-but-inert.
			"transfer-interval": {desc: "Periodic archive interval (minutes)", args: 1,
				valueType: ValueInteger, valueDesc: "Minutes between periodic archives",
				valueExamples: []string{"30", "60", "1440"},
				validator:     ValidateInteger(1, 2880), placeholder: "<minutes>", children: nil},
			// #3984: a repeated keyed-list leaf — an operator writes one
			// `set ... archive-sites <url>` per site and the compiler reads
			// every sibling via FindChildren (compiler_system.go). Without
			// `multi: true` SetPath's single-value-REPLACE branch dropped all
			// but the LAST site on a flat-set / load-set / display-set
			// round-trip. A trailing `password <s>` modifier rides on the
			// leaf's Keys[2:], which the compiler already reads.
			"archive-sites": {desc: "Archive site URL", args: 1, multi: true, placeholder: "<url>", children: nil},
		}},
	}},
	// #4578: master-password is the configstore at-rest-encryption policy
	// knob (configstore.masterPasswordPRF reads the raw AST). The subtree is
	// closed-world (#4313 mechanism) AND leaf-complete — xpf models and
	// consumes exactly one leaf, `pseudorandom-function` — so a typo in the
	// KEYWORD (`pseudo-random-fnuction`) is rejected at commit instead of
	// committing clean and silently DISABLING encryption (masterPasswordPRF
	// would find no `pseudorandom-function` child and fall through to its empty
	// default). The value slot is enum-validated so a typo in the PRF VALUE
	// (`bogus-prf`) is caught too. Scoped strictly to this subtree — the
	// broader `system` open-world behaviour (#4515/X-1) is untouched.
	"master-password": {desc: "Master password", closedWorld: true, children: map[string]*schemaNode{
		"pseudorandom-function": {desc: "Pseudorandom function", args: 1, placeholder: "<function>",
			valueType:     ValueEnumOf,
			valueDesc:     "Master-password key-derivation PRF selector (configstore.prfHash)",
			valueExamples: []string{"hmac-sha2-256", "sha256", "juniper-prf1"},
			validator:     ValidateMasterPasswordPRF,
			children:      nil},
	}},
	"license": {desc: "License configuration", children: map[string]*schemaNode{
		"autoupdate": {desc: "Autoupdate", children: map[string]*schemaNode{
			"url": {desc: "Autoupdate URL", args: 1, placeholder: "<url>", children: nil},
		}},
	}},
	"processes": {desc: "Process information", children: nil},
	"internet-options": {desc: "Internet options", children: map[string]*schemaNode{
		"no-ipv6-reject-zero-hop-limit": {desc: "Do not reject IPv6 packets with zero hop limit", children: nil},
	}},
	"ntp": {desc: "NTP configuration", children: map[string]*schemaNode{
		// #3984: a repeated keyed-list leaf — one `set system ntp server
		// <ip>` per server, and the compiler reads every sibling via
		// FindChildren("server") (compiler_system.go). Without `multi: true`
		// SetPath's single-value-REPLACE branch collapsed a multi-server
		// config to the LAST server on a flat-set / load-set / display-set
		// round-trip.
		// #4902: the NTP server value is rendered verbatim into a chrony
		// `server`/`pool` directive. Type it as an IP-or-hostname so a
		// space/control/malformed value cannot inject a second chrony directive
		// token or fail the chrony reload.
		// #7132: the four Junos per-server MODIFIERS are modeled as children, and
		// the leaf opts into `valueList` so it keeps absorbing a bracket list of
		// SERVERS while descending into the container when the next token names a
		// modifier.
		//
		// Before this, `children: nil` made the two indistinguishable in the AST —
		// measured: `server 1.1.1.1 prefer` and `server [ 1.1.1.1 2.2.2.2 ]` both
		// produced a leaf whose Keys were ["server", <tok>, <tok>], so nothing
		// downstream could tell a modifier from a second server. `prefer` is a
		// syntactically valid hostname, so ValidateNTPServer accepted it too.
		//
		// `valueList` is the existing mechanism for exactly this shape (#3872), not
		// a new one: static `route next-hop` already carries a value slot AND an
		// `interface` modifier child the same way. The SetPath absorber checks
		// `childSchema.children[nextToken]` first (ast_edit.go), so a modeled
		// modifier attaches as a child and everything else is absorbed as a value.
		"server": {desc: "NTP server", args: 1, multi: true, valueList: true, valueType: ValueHostname, valueDesc: "NTP server IP address or hostname", valueExamples: []string{"192.0.2.1", "pool.ntp.org"}, validator: ValidateNTPServer, placeholder: "<address>",
			children: map[string]*schemaNode{
				"prefer":           {desc: "Prefer this server", children: nil},
				"key":              {desc: "Authentication key id for this server", args: 1, placeholder: "<key-id>", valueType: ValueInteger, children: nil},
				"version":          {desc: "NTP version for this server", args: 1, placeholder: "<version>", valueType: ValueInteger, children: nil},
				"routing-instance": {desc: "Routing instance to reach this server in", args: 1, placeholder: "<instance>", children: nil},
			}},
		"threshold": {desc: "Threshold", args: 1, placeholder: "<seconds>",
			valueType: ValueInteger, valueDesc: "NTP step threshold in seconds (>= 1; 0 means 'use the default')",
			valueExamples: []string{"128", "600"},
			// #6940: 0 is the documented default here and consumers gate on > 0,
			// so a silently-zeroed malformed value disabled the threshold action
			// with no diagnostic.
			validator: ValidateIntegerMin(1),
			children: map[string]*schemaNode{
				"action": {desc: "Action on threshold", args: 1, placeholder: "<action>", children: nil},
			}},
	}},
	"syslog": {desc: "Syslog configuration", children: map[string]*schemaNode{
		// #2008 (syslog schema-only): a system syslog host/file/user
		// destination body is a set of `<facility> <severity>` pairs
		// (compiler_system.go syslog loop reads Keys[0]=facility,
		// Keys[1]=severity for every non-`allow-duplicates` child). The
		// facility namespace is open-ended (kern, daemon, auth, local0-7,
		// any, ...) so the FACILITY keyword stays a wildcard — but the
		// SEVERITY value slot is a fixed Junos vocabulary, so a typed
		// wildcard leaf catches a misspelled severity (e.g. `kernel
		// informational`) that the runtime would otherwise treat as "no
		// filter" (ParseSeverity returns 0 for anything it does not know).
		// `allow-duplicates` is an explicit presence-only flag so it is
		// not mistaken for a facility with a missing severity.
		// #4902: the user token is formatted into a drop-in filename
		// (10-xpf-user-<user>.conf) and the rsyslog `:omusrmsg:<user>` directive.
		// A keyValidator (typed KEY slot) rejects a path separator / whitespace /
		// control-char value at commit; the daemon's applySyslogFiles applies the
		// same check defensively.
		"user": {desc: "Syslog user destination", args: 1, placeholder: "<user>",
			keyValueType: ValueIdentifier, keyValueDesc: "Login user name, or '*' for all logged-in users",
			keyValidator: ValidateSyslogUser,
			wildcard:     syslogFacilitySeverityLeaf(),
			children:     syslogDestinationModifiers(nil)},
		"host": {desc: "Syslog host destination", args: 1, placeholder: "<host>",
			wildcard: syslogFacilitySeverityLeaf(),
			// #4303 S-1: host-only modifiers wired into the runtime syslog
			// client (source-address, port). log-prefix / facility-override /
			// routing-instance / exclude-hostname are recognized so a valid
			// vSRX config commits. They are not enforced, and compileSystem
			// raises a commit advisory for each at its skip arm (#9414).
			children: syslogDestinationModifiers(map[string]*schemaNode{
				"source-address": {desc: "Local source address for outgoing syslog", args: 1, placeholder: "<ip>",
					valueType: ValueIPAddress, valueDesc: "IPv4 or IPv6 source address",
					valueExamples: []string{"10.0.1.1", "2001:db8::1"},
					validator:     ValidateIPAddress, children: nil},
				"port": {desc: "Destination syslog port", args: 1, placeholder: "<port>",
					valueType: ValueInteger, valueDesc: "syslog UDP destination port (1-65535)",
					valueExamples: []string{"514", "5514"},
					validator:     ValidateInteger(1, 65535), children: nil},
				"log-prefix":        {desc: "Prefix prepended to each forwarded message", args: 1, placeholder: "<prefix>", children: nil},
				"facility-override": {desc: "Override the facility of forwarded messages", args: 1, placeholder: "<facility>", children: nil},
				"routing-instance":  {desc: "Routing instance used to reach the host", args: 1, placeholder: "<instance>", children: nil},
				"exclude-hostname":  {desc: "Omit the local hostname field", children: nil},
			})},
		// #4902: the file name is formatted into /var/log/<name> and the drop-in
		// filename 10-xpf-<name>.conf. A keyValidator rejects a path separator /
		// `..` / whitespace / control-char value at commit; applySyslogFiles
		// applies the same check defensively.
		"file": {desc: "Syslog file destination", args: 1, placeholder: "<filename>",
			keyValueType: ValueIdentifier, keyValueDesc: "Log file base name (written to /var/log/<name>)",
			keyValidator: ValidateSyslogFileName,
			wildcard:     syslogFacilitySeverityLeaf(),
			children: syslogDestinationModifiers(map[string]*schemaNode{
				"archive": {desc: "Archive-file rotation settings", children: map[string]*schemaNode{
					"size":              {desc: "Maximum file size before rotation", args: 1, placeholder: "<size>", children: nil},
					"files":             {desc: "Number of archive files to retain", args: 1, placeholder: "<count>", children: nil},
					"world-readable":    {desc: "Archives readable by all users", children: nil},
					"no-world-readable": {desc: "Archives readable only by root", children: nil},
					"start-time":        {desc: "Scheduled archive start time", args: 1, placeholder: "<time>", children: nil},
					"transfer-interval": {desc: "Periodic archive interval (minutes)", args: 1, placeholder: "<minutes>", children: nil},
					"archive-sites":     {desc: "Off-box archive site URL", args: 1, multi: true, placeholder: "<url>", children: nil},
				}},
			})},
	}},
	"login": {desc: "Login configuration", children: map[string]*schemaNode{
		// #4304 S-2: custom `login class <name>` RBAC definition. Recognized so
		// a real vSRX config commits; the Junos permission set is mapped onto
		// xpf's coarse permission model at compile (compiler_system.go).
		//
		// The four regex leaves are accepted STRUCTURALLY here but split at
		// compile (#5831): the ADDITIVE allow-commands / allow-configuration
		// stay recognized-but-not-enforced with the #4304 advisory, while the
		// RESTRICTIVE deny-commands / deny-configuration are hard-REJECTED at
		// commit (validateLoginClassDenyStrict) and fold the class toward the
		// repair floor on the tolerant load / peer-sync path. Structural
		// acceptance is deliberate: the schema must still parse the leaf so
		// the compiler can produce the actionable rejection rather than an
		// opaque "unknown statement".
		"class": {desc: "Login class definition", args: 1, placeholder: "<class-name>", closedWorld: true, children: map[string]*schemaNode{
			"permissions":         {desc: "Permission bits granted to the class", args: 1, multi: true, placeholder: "<permission>", children: nil},
			"idle-timeout":        {desc: "Idle timeout (minutes)", args: 1, placeholder: "<minutes>", valueType: ValueInteger, validator: ValidateInteger(0, 4294967295), children: nil},
			"allow-commands":      {desc: "Regex of operational commands to allow", args: 1, placeholder: "<regex>", children: nil},
			"deny-commands":       {desc: "Regex of operational commands to deny", args: 1, placeholder: "<regex>", children: nil},
			"allow-configuration": {desc: "Regex of configuration to allow", args: 1, placeholder: "<regex>", children: nil},
			"deny-configuration":  {desc: "Regex of configuration to deny", args: 1, placeholder: "<regex>", children: nil},
			// #7971: modeled ONLY so they are REFUSED. Not a step toward
			// implementing the family — see schema_login_regexps_7971.go.
			"allow-commands-regexps":      unimplementedRegexpsLeaf("allow-commands-regexps"),
			"deny-commands-regexps":       unimplementedRegexpsLeaf("deny-commands-regexps"),
			"allow-configuration-regexps": unimplementedRegexpsLeaf("allow-configuration-regexps"),
			"deny-configuration-regexps":  unimplementedRegexpsLeaf("deny-configuration-regexps"),
			"login-alarms":                {desc: "Display system alarms on login", children: nil},
			"login-tip":                   {desc: "Display a tip on login", children: nil},
		}},
		// #4895: the login user NAME is a keyed identity token that the daemon
		// formats verbatim into an /etc/sudoers.d/xpf-<name> NOPASSWD grant.
		// The lexer decodes `\n` inside a quoted string into a literal newline,
		// so an unvalidated name can inject additional sudoers directives. The
		// keyValidator (typed KEY slot, #1319 PR 3) validates the identity arg
		// token against a safe POSIX account-name shape at commit-check —
		// strict on commit, warn on the tolerant load/sync path (#1960). The
		// daemon's writeSudoersGrant/reconcileSudoers apply the SAME check
		// defensively so a leniently-loaded name still never reaches sudoers.
		"user": {desc: "User name", args: 1, placeholder: "<username>",
			keyValueType: ValueIdentifier, keyValueDesc: "POSIX login user name (lowercase letter/underscore then [a-z0-9_-])",
			keyValidator: ValidateLoginUsername, children: map[string]*schemaNode{
				"uid": {desc: "User ID", args: 1, placeholder: "<uid>", children: nil},
				// #2008 H6 / #4304 S-2: the class is validated against the
				// system-defined built-ins UNION any custom `login class <name>`
				// defined in the SAME candidate tree. The tree-aware validator
				// replaces the fixed enum so a valid custom-RBAC config is no
				// longer hard-rejected at commit, while an undefined class still
				// fails closed. RBAC enforcement is in pkg/cli/permissions.go.
				"class": {desc: "Login class", args: 1, placeholder: "<class>",
					valueType: ValueEnumOf, valueDesc: "System-defined class (super-user | operator | read-only | config-viewer | unauthorized) or a custom `login class <name>`",
					valueExamples: []string{"super-user", "operator", "read-only"},
					treeValidator: validateLoginClassRef, children: nil},
				// #1944: close the schema asymmetry the compiler already
				// half-implemented — give `authentication` a value-bearing
				// children map (encrypted-password typed leaf + ssh-* keys).
				"authentication": {desc: "Authentication methods", children: map[string]*schemaNode{
					"encrypted-password": {desc: "Encrypted password", args: 1, placeholder: "<crypt-hash>",
						valueType: ValueCryptHash, validator: ValidateCryptHash, children: nil},
					"ssh-ed25519": {desc: "SSH ED25519 public key", args: 1, multi: true, placeholder: "<key>", children: nil},
					"ssh-rsa":     {desc: "SSH RSA public key", args: 1, multi: true, placeholder: "<key>", children: nil},
					"ssh-dsa":     {desc: "SSH DSA public key", args: 1, multi: true, placeholder: "<key>", children: nil},
				}},
			}},
	}},
	"dataplane-type": {desc: "Dataplane type", args: 1, placeholder: "<type>", children: nil},
	"dataplane": {desc: "Dataplane configuration", children: map[string]*schemaNode{
		// cores / memory / socket-mem / rx-mode / ports are DPDK-era
		// knobs whose consumer was deleted in the #1525 retirement —
		// compileUserspaceDataplane has no case for any of them. They
		// stay in the grammar for stored-config compatibility (never
		// break an existing stanza) but have NO effect; the compiler
		// emits a per-knob commit warning instead (#1892,
		// userspaceRetiredKnobWarnings).
		"cores":      {args: 1, desc: "Legacy DPDK core count (retired, ignored)", children: nil},
		"memory":     {args: 1, desc: "Legacy DPDK memory allocation (retired, ignored)", children: nil},
		"socket-mem": {args: 1, desc: "Legacy DPDK socket memory (retired, ignored)", children: nil},
		"binary":     {args: 1, desc: "Userspace dataplane helper binary path", children: nil},
		// #5839: typed so a path the dataplane bring-up would have to refuse
		// — relative, `..`-escaping, or over the AF_UNIX sun_path limit —
		// fails at commit check instead of at helper start. Strict commits
		// only; the tolerant load path warns and boots (#1960), and
		// removeStaleUnixSocket re-judges the path defensively at runtime.
		"control-socket": {
			args:          1,
			desc:          "Unix control socket path",
			valueType:     ValueUnixSocketPath,
			valueDesc:     "Absolute path the dataplane helper binds its control socket at",
			valueExamples: []string{"/run/xpf/userspace-dp.sock"},
			validator:     ValidateUnixSocketPath,
			children:      nil,
		},
		"state-file": {args: 1, desc: "Helper state file path", children: nil},
		// #1319 PR 3 typed dataplane knobs. Each compiled with the
		// Atoi error swallowed (compileUserspaceDataplane), so
		// garbage silently fell back to the 0 zero-value, which the
		// manager coerces to the default (workers<=0 -> 1,
		// ring-entries<=0 -> 1024; pkg/dataplane/userspace/
		// manager.go capabilities.go). `workers` stays min-only (the
		// runtime owns its ceiling); `ring-entries` is bounded both
		// ways and required power-of-two as of #2524, because it sizes
		// per-binding UMEM preallocations directly (an unbounded value
		// OOM'd at bring-up rather than failing at commit).
		"workers": {
			args:          1,
			desc:          "Worker thread count",
			valueType:     ValueInteger,
			valueDesc:     "Dataplane worker thread count (>= 1)",
			valueExamples: []string{"4", "6"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"ring-entries": {
			args:          1,
			desc:          "AF_XDP ring entries per queue",
			valueType:     ValueInteger,
			valueDesc:     "AF_XDP ring entries per queue (power of two in [1..16384])",
			valueExamples: []string{"1024", "2048"},
			// #2524: bound [1..MaxRingEntries] AND power-of-two. The
			// helper preallocates ~3×ring_entries UMEM frames per binding
			// (bind.rs), so an unbounded value OOM'd at bring-up instead
			// of failing as a clean commit error.
			validator: ValidateRingEntries,
			children:  nil,
		},
		// Only these two strings are acted on; anything else was
		// silently ignored (compiler_system.go poll-mode case).
		"poll-mode": {
			args:          1,
			desc:          "Worker poll mode (busy-poll or interrupt)",
			valueType:     ValueEnumOf,
			valueDesc:     "Worker poll mode (busy-poll | interrupt)",
			valueExamples: []string{"busy-poll", "interrupt"},
			validator:     ValidateEnum([]string{"busy-poll", "interrupt"}),
			children:      nil,
		},
		"shared-umem": {desc: "AF_XDP shared-UMEM policy override", children: map[string]*schemaNode{
			"mode":                 {args: 1, desc: "Shared UMEM mode override (auto|off|same-device-debug|cross-nic)", children: nil},
			"interface":            {args: 1, multi: true, desc: "Optional participating Linux interface filter", children: nil},
			"phase0-artifact-file": {args: 1, desc: "Optional machine-readable Phase 0 audit artifact", children: nil},
			"artifact-file":        {args: 1, desc: "Alias for phase0-artifact-file", children: nil},
		}},
		// Only the literal "disable" acts; any other string
		// (including typos) silently meant the enabled default.
		"rss-indirection": {
			args:          1,
			desc:          "mlx5 RSS indirection reshaping (enable|disable)",
			valueType:     ValueEnumOf,
			valueDesc:     "RSS indirection reshaping (enable | disable; default enable)",
			valueExamples: []string{"enable", "disable"},
			validator:     ValidateEnum([]string{"enable", "disable"}),
			children:      nil,
		},
		// Only the literal "true" opts in (#801 B1 gate); any other
		// string silently meant false.
		"claim-host-tunables": {
			args:          1,
			desc:          "Allow xpfd to write host-scope tunables (true|false, default false)",
			valueType:     ValueBool,
			valueDesc:     "Write host-scope tunables (true | false; default false)",
			valueExamples: []string{"true", "false"},
			validator:     ValidateEnum([]string{"true", "false"}),
			children:      nil,
		},
		// cpu-governor stays untyped BY DESIGN: the compiler passes
		// unrecognised governors through so bare-metal operators can
		// request powersave/ondemand without a schema change
		// (compiler_system.go cpu-governor case).
		"cpu-governor": {args: 1, desc: "Host cpufreq governor (performance|schedutil|default; other governors pass through verbatim)", children: nil},
		// 0 is the "use default" zero-value sentinel
		// (resolvedHostTunables, pkg/daemon/host_tunables.go:494),
		// so garbage silently meant the default budget.
		"netdev-budget": {
			args:          1,
			desc:          "net.core.netdev_budget value",
			valueType:     ValueInteger,
			valueDesc:     "net.core.netdev_budget (>= 1)",
			valueExamples: []string{"600"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"coalescence": {desc: "NIC interrupt-coalescence tuning (mlx5)", children: map[string]*schemaNode{
			// Anything but the literal "enable" silently meant
			// disable (compiler_system.go coalescence case); the
			// usec knobs treat <= 0 as "use default"
			// (pkg/daemon/coalescence.go:60-65), so garbage
			// silently fell back too.
			"adaptive": {
				args:          1,
				desc:          "Adaptive coalescing (enable|disable)",
				valueType:     ValueEnumOf,
				valueDesc:     "Adaptive interrupt coalescing (enable | disable)",
				valueExamples: []string{"enable", "disable"},
				validator:     ValidateEnum([]string{"enable", "disable"}),
				children:      nil,
			},
			"rx-usecs": {
				args:          1,
				desc:          "RX coalescing µs",
				valueType:     ValueInteger,
				valueDesc:     "RX interrupt coalescing in microseconds (>= 1)",
				valueExamples: []string{"8"},
				validator:     ValidateIntegerMin(1),
				children:      nil,
			},
			"tx-usecs": {
				args:          1,
				desc:          "TX coalescing µs",
				valueType:     ValueInteger,
				valueDesc:     "TX interrupt coalescing in microseconds (>= 1)",
				valueExamples: []string{"8"},
				validator:     ValidateIntegerMin(1),
				children:      nil,
			},
		}},
		"rx-mode": {desc: "Legacy DPDK adaptive RX mode (retired, ignored)", children: map[string]*schemaNode{
			"idle-threshold":   {args: 1, desc: "Legacy DPDK RX idle threshold (retired, ignored)", children: nil},
			"resume-threshold": {args: 1, desc: "Legacy DPDK RX resume threshold (retired, ignored)", children: nil},
			"sleep-timeout":    {args: 1, desc: "Legacy DPDK RX sleep timeout (retired, ignored)", children: nil},
		}},
		"ports": {desc: "Legacy DPDK per-port mapping (retired, ignored)", wildcard: &schemaNode{desc: "Legacy DPDK port name (retired, ignored)", placeholder: "<port-name>", children: map[string]*schemaNode{
			"interface": {args: 1, desc: "Legacy DPDK port interface binding (retired, ignored)", children: nil},
			"rx-mode":   {args: 1, desc: "Legacy DPDK per-port RX mode (retired, ignored)", children: nil},
			"cores":     {args: 1, desc: "Legacy DPDK per-port core list (retired, ignored)", children: nil},
		}}},
	}},
	"services": {desc: "System services", children: map[string]*schemaNode{
		"ssh": {desc: "SSH service", children: map[string]*schemaNode{
			// Only allow/deny/deny-password map to sshd
			// PermitRootLogin values; anything else was a silent
			// no-op (pkg/daemon/daemon_system.go:739-748). The old
			// "<permit|deny>" placeholder named values the runtime
			// never accepted.
			"root-login": {
				desc:          "Root login permission",
				args:          1,
				placeholder:   "<allow|deny|deny-password>",
				valueType:     ValueEnumOf,
				valueDesc:     "Root SSH login policy (allow | deny | deny-password)",
				valueExamples: []string{"allow", "deny", "deny-password"},
				validator:     ValidateEnum([]string{"allow", "deny", "deny-password"}),
				children:      nil,
			},
			// H5 (#2008): repeatable key-exchange method → sshd
			// KexAlgorithms (pkg/daemon/daemon_system.go applySSHConfig).
			// Junos takes a free-form algorithm-name list; sshd validates
			// the spellings at reload, so no enum here.
			// #4902: the key-exchange list is joined with commas into a sshd
			// `KexAlgorithms` line. Type each token as a safe OpenSSH algorithm
			// name so a value with a comma/space/control char cannot smuggle a
			// second sshd directive token onto the line (or fail the reload). sshd
			// still validates the algorithm SPELLING at reload; this only rejects
			// the injection/breakage shape.
			"key-exchange": {
				desc:          "SSH key-exchange method (KexAlgorithms)",
				args:          1,
				multi:         true,
				placeholder:   "<key-exchange-method>",
				valueType:     ValueIdentifier,
				valueDesc:     "OpenSSH key-exchange algorithm name; QUOTE a name containing @ — the lexer rejects a bare @",
				valueExamples: []string{"curve25519-sha256", "diffie-hellman-group-exchange-sha256"},
				validator:     ValidateSSHAlgorithm,
				children:      nil,
			},
			// #4305 S-4: sshd hardening knobs rendered into the xpf drop-in.
			// #4902: ciphers/macs are comma-joined into sshd Ciphers/MACs lines,
			// so each token is a typed safe algorithm name (same rationale as
			// key-exchange above). sshd validates the spellings at reload.
			"ciphers": {desc: "SSH ciphers (sshd Ciphers)", args: 1, multi: true,
				valueType: ValueIdentifier, valueDesc: "OpenSSH cipher name; QUOTE a name containing @ — the lexer rejects a bare @",
				valueExamples: []string{`"aes256-gcm@openssh.com"`, `"chacha20-poly1305@openssh.com"`},
				validator:     ValidateSSHAlgorithm, placeholder: "<cipher>", children: nil},
			"macs": {desc: "SSH message-authentication codes (sshd MACs)", args: 1, multi: true,
				valueType: ValueIdentifier, valueDesc: "OpenSSH MAC name; QUOTE a name containing @ — the lexer rejects a bare @",
				valueExamples: []string{`"hmac-sha2-256-etm@openssh.com"`, "hmac-sha2-512"},
				validator:     ValidateSSHAlgorithm, placeholder: "<mac>", children: nil},
			"connection-limit": {desc: "Maximum concurrent SSH connections (sshd MaxStartups)", args: 1, placeholder: "<limit>",
				valueType: ValueInteger, valueDesc: "1-250", validator: ValidateInteger(1, 250), children: nil},
			"rate-limit": {desc: "SSH connection attempts per minute", args: 1, placeholder: "<limit>",
				valueType: ValueInteger, valueDesc: "1-250", validator: ValidateInteger(1, 250), children: nil},
			"client-alive-interval": {desc: "sshd ClientAliveInterval (seconds; 0 disables)", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "0-65535", validator: ValidateInteger(0, 65535), children: nil},
			"client-alive-count-max": {desc: "sshd ClientAliveCountMax", args: 1, placeholder: "<count>",
				valueType: ValueInteger, valueDesc: "0-255", validator: ValidateInteger(0, 255), children: nil},
			"protocol-version": {desc: "SSH protocol version (sshd is SSH-2 only)", args: 1, placeholder: "<version>",
				valueType: ValueEnumOf, valueDesc: "v1 | v2", valueExamples: []string{"v2"},
				validator: ValidateEnum([]string{"v1", "v2"}), children: nil},
		}},
		"netconf": {desc: "NETCONF service", children: map[string]*schemaNode{
			"ssh": {desc: "NETCONF over SSH", children: nil},
		}},
		"web-management": {desc: "Web management", children: map[string]*schemaNode{
			"http": {desc: "HTTP service", children: map[string]*schemaNode{
				"interface": {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
			}},
			"https": {desc: "HTTPS service", children: map[string]*schemaNode{
				"system-generated-certificate": {desc: "Use system-generated certificate", children: nil},
				"interface":                    {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
			}},
			"api-auth": {desc: "API authentication", children: map[string]*schemaNode{
				"user": {desc: "User name", wildcard: &schemaNode{desc: "Basic-auth user name for the REST API", placeholder: "<username>", children: map[string]*schemaNode{
					"password": {desc: "Password", args: 1, placeholder: "<password>", children: nil},
				}}},
				// #3984: repeated keyed-list leaf — the compiler accumulates
				// every `api-key` sibling into APIAuth.APIKeys via
				// FindChildren (compiler_system.go). `multi: true` keeps each
				// `set ... api-key <key>` a distinct sibling instead of
				// replacing the previous one.
				"api-key": {desc: "API key", args: 1, multi: true, placeholder: "<key>", children: nil},
			}},
		}},
		"dns": {desc: "DNS service", children: nil},
		// packedTail (#6821): compileDHCPLocalServer reads this container's
		// packed tail (`dhcp-local-server dhcp-socket-type udp;`), so the
		// walker must validate the same expansion. Without the pairing the
		// compact spelling would compile UNVALIDATED while the block spelling
		// is enum-checked.
		"dhcp-local-server": {desc: "DHCP local server", packedTail: true, children: map[string]*schemaNode{
			"group":                     dhcpLocalServerGroupSchema("DHCP"),
			"dynamic-dns":               dhcpDynamicDNSSchema(),
			"expired-leases-processing": dhcpExpiredLeasesSchema(),
			// #7318: IPv4-only. Kea's Dhcp6 has no raw mode, so there is
			// deliberately no sibling under dhcpv6-local-server. Absent ==
			// Kea's default `raw` == today's behaviour; `udp` is the opt-in
			// that makes DHCPv4 traverse the netfilter input hook, at the
			// cost of no longer serving directly-attached address-less
			// clients (validateDHCPSocketTypeWarnings states the trade).
			"dhcp-socket-type": {desc: "Kea DHCPv4 receive socket type", args: 1, scalar: true,
				placeholder:   "<socket-type>",
				valueType:     ValueEnumOf,
				valueDesc:     "raw (default; AF_PACKET, ungateable by netfilter) | udp (relayed traffic only)",
				valueExamples: []string{"raw", "udp"},
				validator:     ValidateEnum(dhcpSocketTypes),
				children:      nil},
		}},
		"dhcpv6-local-server": {desc: "DHCPv6 local server", children: map[string]*schemaNode{
			"group":                     dhcpLocalServerGroupSchema("DHCPv6"),
			"dynamic-dns":               dhcpDynamicDNSSchema(),
			"expired-leases-processing": dhcpExpiredLeasesSchema(),
		}},
		"dynamic-dns": ddnsServicesSchema(),
	}},
}}

var schemaServices = &schemaNode{desc: "Services configuration", children: map[string]*schemaNode{
	"rpm": {desc: "Real-time Performance Monitoring probes", children: map[string]*schemaNode{
		// #1319 PR 3: the rpm integer knobs already fail compile
		// loudly via parseRPMPositiveInt (> 0 enforced); typing them
		// surfaces the same bound at `?` completion and rejects in
		// the uniform schema-gate error shape before compile.
		"probe-limit": {
			args:          1,
			desc:          "Default maximum consecutive failed probes before stopping a test cycle",
			valueType:     ValueInteger,
			valueDesc:     "Maximum consecutive failed probes (>= 1)",
			valueExamples: []string{"3"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"probe": {args: 1, desc: "RPM probe name", children: map[string]*schemaNode{
			"test": {args: 1, desc: "RPM test name", children: map[string]*schemaNode{
				// Mirrors supportedRPMProbeTypes
				// (compiler_services.go:10) which the compiler
				// already rejects loudly.
				"probe-type": {
					args:          1,
					desc:          "Probe type: icmp-ping, tcp-ping, or http-get",
					valueType:     ValueEnumOf,
					valueDesc:     "Probe type (icmp-ping | tcp-ping | http-get)",
					valueExamples: []string{"icmp-ping", "tcp-ping", "http-get"},
					validator:     ValidateEnum([]string{"icmp-ping", "tcp-ping", "http-get"}),
					children:      nil,
				},
				"target":                {desc: "Target IP, hostname, or URL", wildcard: &schemaNode{placeholder: "<target>", desc: "Target IP, hostname, or URL"}, children: map[string]*schemaNode{"url": {args: 1, desc: "HTTP target URL", children: nil}, "address": {args: 1, desc: "Target IP address (canonical Junos form)", children: nil}}},
				"source-address":        {args: 1, desc: "Source address for the probe", children: nil},
				"routing-instance":      {args: 1, desc: "Routing instance / VRF for the probe", children: nil},
				"destination-interface": {args: 1, desc: "Egress interface to pin the probe to", children: nil},
				"next-hop":              {args: 1, desc: "Next-hop IP to pin the probe via (reserved probe routing table)", children: nil},
				"probe-interval": {
					args:          1,
					desc:          "Seconds between probes within a test",
					valueType:     ValueInteger,
					valueDesc:     "Seconds between probes (1..MaxDurationSeconds)",
					valueExamples: []string{"5"},
					// #5723: bound the upper end (not just >= 1) so a
					// pathological value cannot overflow
					// time.Duration(sec)*time.Second into a non-positive Duration
					// at the runtime probe loop (time.NewTicker / time.After panic
					// / busy-spin) — sibling of the #5705 keepalive crash. Same
					// MaxDurationSeconds ceiling the feeds update/hold-interval and
					// other second-valued leaves use.
					validator: ValidateInteger(1, MaxDurationSeconds),
					children:  nil,
				},
				"probe-count": {
					args:          1,
					desc:          "Number of probes per test cycle",
					valueType:     ValueInteger,
					valueDesc:     "Probes per test cycle (>= 1)",
					valueExamples: []string{"3"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				"test-interval": {
					args:          1,
					desc:          "Seconds between test cycles",
					valueType:     ValueInteger,
					valueDesc:     "Seconds between test cycles (1..MaxDurationSeconds)",
					valueExamples: []string{"30"},
					// #5723: bound the upper end so a pathological value cannot
					// overflow time.Duration(sec)*time.Second into a non-positive
					// Duration and panic time.NewTicker in the runtime probe loop
					// (rpm.go runProbeLoop) — a commit-reachable xpfd crash,
					// sibling of the #5705 keepalive overflow.
					validator: ValidateInteger(1, MaxDurationSeconds),
					children:  nil,
				},
				"thresholds": {desc: "Failure thresholds for the test", children: map[string]*schemaNode{
					"successive-loss": {
						args:          1,
						desc:          "Consecutive losses before marking the test failed",
						valueType:     ValueInteger,
						valueDesc:     "Consecutive losses before failure (>= 1)",
						valueExamples: []string{"3"},
						validator:     ValidateIntegerMin(1),
						children:      nil,
					},
				}},
				"probe-limit": {
					args:          1,
					desc:          "Maximum consecutive failed probes before stopping the current test cycle",
					valueType:     ValueInteger,
					valueDesc:     "Maximum consecutive failed probes (>= 1)",
					valueExamples: []string{"3"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				// The compiler only enforces > 0; the TCP port wire
				// encoding is 16 bits, so 65536+ dialed and failed
				// silently at probe runtime.
				"destination-port": {
					args:          1,
					desc:          "Destination TCP port for tcp-ping probes",
					valueType:     ValueInteger,
					valueDesc:     "Destination TCP port (1..65535)",
					valueExamples: []string{"443"},
					validator:     ValidateInteger(1, 65535),
					children:      nil,
				},
			}},
		}},
	}},
	"ip-monitoring": {desc: "IP monitoring: probe-driven preferred-route failover", children: map[string]*schemaNode{
		"policy": {args: 1, desc: "IP monitoring policy name", placeholder: "<policy-name>", children: map[string]*schemaNode{
			"match": {desc: "Match conditions", children: map[string]*schemaNode{
				"rpm-probe": {args: 1, desc: "RPM probe whose test failures trigger this policy", placeholder: "<probe-name>", children: nil},
			}},
			"then": {desc: "Actions while the matched probe is FAILED", children: map[string]*schemaNode{
				"preferred-route": {desc: "Preferred routes injected at route preference 1", children: map[string]*schemaNode{
					"route": {args: 1, desc: "Destination prefix to inject", placeholder: "<prefix>", children: map[string]*schemaNode{
						"next-hop": {args: 1, desc: "Next-hop IP for the injected route, or a DHCP interface unit (<ifd>.<unit>) to track its learned gateway", children: nil},
						// Min-only, mirroring the compiler's loud
						// >= 0 check; the metric is a pure in-memory
						// tie-break comparator (pkg/ipmon/ipmon.go:361),
						// never wire-encoded.
						"preferred-metric": {
							args:          1,
							desc:          "Metric among injected routes for the same prefix (tie-break)",
							valueType:     ValueInteger,
							valueDesc:     "Tie-break metric among injected routes (>= 0)",
							valueExamples: []string{"10"},
							validator:     ValidateIntegerMin(0),
							children:      nil,
						},
					}},
					"routing-instance": {args: 1, desc: "Inject into a routing instance", placeholder: "<instance>", children: map[string]*schemaNode{
						"route": {args: 1, desc: "Destination prefix to inject", placeholder: "<prefix>", children: map[string]*schemaNode{
							"next-hop": {args: 1, desc: "Next-hop IP for the injected route, or a DHCP interface unit (<ifd>.<unit>) to track its learned gateway", children: nil},
							// See the sibling preferred-metric note.
							"preferred-metric": {
								args:          1,
								desc:          "Metric among injected routes for the same prefix (tie-break)",
								valueType:     ValueInteger,
								valueDesc:     "Tie-break metric among injected routes (>= 0)",
								valueExamples: []string{"10"},
								validator:     ValidateIntegerMin(0),
								children:      nil,
							},
						}},
					}},
				}},
			}},
			// The compiler rejects negatives loudly; the runtime
			// converts to time.Duration (pkg/ipmon/ipmon.go:480), so
			// the only genuine ceiling is the Duration-overflow
			// point (MaxDurationSeconds) — past it the hold went
			// negative and silently inverted the damping.
			"hold-down": {
				args:          1,
				desc:          "Seconds to damp recovery before withdrawing routes (0 = immediate, Junos parity)",
				valueType:     ValueInteger,
				valueDesc:     "Recovery damping in seconds (>= 0; 0 = immediate)",
				valueExamples: []string{"0", "30"},
				validator:     ValidateInteger(0, MaxDurationSeconds),
				children:      nil,
			},
		}},
	}},
	"flow-monitoring": {desc: "Flow export (NetFlow v9 / IPFIX) template configuration", children: map[string]*schemaNode{
		"version9": {desc: "NetFlow version 9 export", children: map[string]*schemaNode{
			"template": {desc: "NetFlow v9 flow record template", args: 1, placeholder: "<template-name>", children: map[string]*schemaNode{
				// #1979 Layer B (Tier 1): FlowActiveTimeout/InactiveTimeout
				// reach the Rust u32 ActiveTimeout/InactiveTimeout wire fields
				// via buildFlowExportSnapshot (Layer A caps <0->0, >u32max->
				// u32max, flow.go coerceWireU32Timeout). Reject the out-of-
				// range value at commit instead of silently coercing it.
				"flow-active-timeout": {desc: "Active flow export timeout in seconds (default 60)", args: 1, placeholder: "<seconds>",
					valueType: ValueInteger, valueDesc: "Active flow export timeout in seconds (0..4294967295)",
					valueExamples: []string{"60"}, validator: ValidateInteger(0, maxWireU32), children: nil},
				"flow-inactive-timeout": {desc: "Inactive flow export timeout in seconds (default 15)", args: 1, placeholder: "<seconds>",
					valueType: ValueInteger, valueDesc: "Inactive flow export timeout in seconds (0..4294967295)",
					valueExamples: []string{"15"}, validator: ValidateInteger(0, maxWireU32), children: nil},
				// #6769: typed at MaxDurationSeconds. This leaf was the one
				// untyped member of the trio — its two siblings above already
				// carry ValidateInteger — so a `seconds` value large enough to
				// overflow `time.Duration(n) * time.Second` reached
				// pkg/flowexport, wrapped, and became a SUB-SECOND template
				// ticker (20211507185753197 -> 512ns) that re-exports templates
				// thousands of times a second at every collector. The ceiling is
				// the runtime-derived overflow point, not a policy cap.
				"template-refresh-rate": {desc: "Interval between template re-exports", children: map[string]*schemaNode{
					"seconds": {desc: "Template refresh interval in seconds (default 60)", args: 1, placeholder: "<seconds>",
						valueType: ValueInteger, valueDesc: "Template refresh interval in seconds (0..9223372036; 0 = default 60)",
						valueExamples: []string{"60"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
				}},
			}},
		}},
		"version-ipfix": {desc: "IPFIX flow export", children: map[string]*schemaNode{
			"template": {desc: "IPFIX flow record template", args: 1, placeholder: "<template-name>", children: map[string]*schemaNode{
				// #1979 Layer B (Tier 1, §4b): the IPFIX timeouts do NOT reach
				// the wire (buildFlowExportSnapshot reads only fm.Version9,
				// flow.go), so this is UX parity only — but typing them is the
				// same one-line change and keeps the two template families
				// consistent. The Layer-A-agreement property test EXCLUDES
				// these (not wire-reaching); plain accept/reject covers them.
				"flow-active-timeout": {desc: "Active flow export timeout in seconds (default 60)", args: 1, placeholder: "<seconds>",
					valueType: ValueInteger, valueDesc: "Active flow export timeout in seconds (0..4294967295)",
					valueExamples: []string{"60"}, validator: ValidateInteger(0, maxWireU32), children: nil},
				"flow-inactive-timeout": {desc: "Inactive flow export timeout in seconds (default 15)", args: 1, placeholder: "<seconds>",
					valueType: ValueInteger, valueDesc: "Inactive flow export timeout in seconds (0..4294967295)",
					valueExamples: []string{"15"}, validator: ValidateInteger(0, maxWireU32), children: nil},
				// #6769: typed at MaxDurationSeconds. This leaf was the one
				// untyped member of the trio — its two siblings above already
				// carry ValidateInteger — so a `seconds` value large enough to
				// overflow `time.Duration(n) * time.Second` reached
				// pkg/flowexport, wrapped, and became a SUB-SECOND template
				// ticker (20211507185753197 -> 512ns) that re-exports templates
				// thousands of times a second at every collector. The ceiling is
				// the runtime-derived overflow point, not a policy cap.
				"template-refresh-rate": {desc: "Interval between template re-exports", children: map[string]*schemaNode{
					"seconds": {desc: "Template refresh interval in seconds (default 60)", args: 1, placeholder: "<seconds>",
						valueType: ValueInteger, valueDesc: "Template refresh interval in seconds (0..9223372036; 0 = default 60)",
						valueExamples: []string{"60"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
				}},
				"ipv4-template": {desc: "IPv4 flow record template options", children: map[string]*schemaNode{
					"export-extension": {desc: "Export extension (accepted; not applied to IPFIX records)", args: 1, placeholder: "<extension>", children: nil},
				}},
				"ipv6-template": {desc: "IPv6 flow record template options", children: map[string]*schemaNode{
					"export-extension": {desc: "Export extension (accepted; not applied to IPFIX records)", args: 1, placeholder: "<extension>", children: nil},
				}},
			}},
		}},
	}},
	"application-identification": {desc: "Enable application identification against the predefined application catalog (port/protocol matching; no L7 DPI)", children: nil},
}}

// dhcpDynamicDNSSchema returns the typed-leaf schema for the #1387
// DHCP dynamic-DNS block, shared by dhcp-local-server and
// dhcpv6-local-server. Returned as a fresh tree per call so the two
// parents do not share a mutable map. The enums + ttl carry validators
// (the compiler/runtime consume them); the free-form credential and
// target fields (domain, update-server, tsig-*) stay untyped so a valid
// hostname / base64 secret is not rejected at commit — the live rfc2136
// backend that consumes them is warn-validated at commit
// (validateDDNSBackendWarnings) and fail-open at runtime, never a hard
// brick.
func dhcpDynamicDNSSchema() *schemaNode {
	return &schemaNode{desc: "Dynamic DNS updates for DHCP leases (#1387)", children: map[string]*schemaNode{
		"enable": {desc: "Enable dynamic DNS record publishing", children: nil},
		"domain": {
			desc:        "Default DNS domain appended to non-FQDN client names",
			args:        1,
			placeholder: "<domain>",
			children:    nil,
		},
		"ttl": {
			desc:          "TTL (seconds) for published A/AAAA/PTR records (default 300)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Record TTL in seconds (1..4294967295; default 300 when unset)",
			valueExamples: []string{"300", "3600"},
			// #6773: bounded at the DNS wire domain. The RR header TTL is a
			// 32-bit unsigned field, so a larger value WRAPS rather than
			// failing — 2^32 lands as 0, telling every resolver not to cache
			// the record. Min-only admitted exactly that.
			validator: ValidateInteger(1, MaxDNSTTLSeconds),
			children:  nil,
		},
		"hostname-source": {
			desc:          "How the published label is derived from the lease",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Label source (client-hostname | fqdn | mac-fallback)",
			valueExamples: []string{"client-hostname", "fqdn", "mac-fallback"},
			validator:     ValidateEnum([]string{"client-hostname", "fqdn", "mac-fallback"}),
			children:      nil,
		},
		"conflict-policy": {
			desc:          "Behaviour on a colliding existing record",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Conflict policy (replace-owned | skip-existing | strict-fail)",
			valueExamples: []string{"replace-owned", "skip-existing", "strict-fail"},
			validator:     ValidateEnum([]string{"replace-owned", "skip-existing", "strict-fail"}),
			children:      nil,
		},
		"backend": {
			desc:          "DNS-update backend (rfc2136 is live; kea-d2 is reserved/unimplemented)",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Update backend (rfc2136 [live] | kea-d2 [reserved, not in image])",
			valueExamples: []string{"rfc2136"},
			validator:     ValidateEnum([]string{"rfc2136", "kea-d2"}),
			children:      nil,
		},
		"update-server": {
			desc:        "Authoritative DNS target for RFC 2136 updates (host[:port])",
			args:        1,
			placeholder: "<host[:port]>",
			children:    nil,
		},
		"tsig-key": {
			desc:        "TSIG key name for authenticated updates",
			args:        1,
			placeholder: "<key-name>",
			children:    nil,
		},
		"tsig-algorithm": {
			desc:        "TSIG algorithm (e.g. hmac-sha256)",
			args:        1,
			placeholder: "<algorithm>",
			children:    nil,
		},
		"tsig-secret": {
			desc:        "TSIG shared secret (sensitive; redacted in show output)",
			args:        1,
			placeholder: "<secret>",
			children:    nil,
		},
		// #2691 P1b / #2665: source/VRF binding for the RFC 2136 UPDATE
		// transport (multi-WAN / VRF parity). All three are free-form leaves
		// (an IP literal / interface name / routing-instance name) — the live
		// backend builds a custom net.Dialer (LocalAddr + SO_BINDTODEVICE / VRF
		// bind) from them; an unusable value is fail-open at runtime (logged,
		// the update falls back to the default table), never a hard commit
		// brick — matching the existing update-server / tsig-* leaves.
		"source-address": {
			desc:        "Source address to bind the RFC 2136 UPDATE socket to (#2665)",
			args:        1,
			placeholder: "<ip>",
			children:    nil,
		},
		"destination-interface": {
			desc:        "Egress interface to pin the RFC 2136 UPDATE to (SO_BINDTODEVICE, #2665)",
			args:        1,
			placeholder: "<interface>",
			children:    nil,
		},
		"routing-instance": {
			desc:        "Routing instance / VRF the RFC 2136 UPDATE egresses from (#2665)",
			args:        1,
			placeholder: "<instance>",
			children:    nil,
		},
	}}
}

// ddnsServicesSchema returns the config-mode schema for the Surface A
// `system services dynamic-dns` provider catalog + engine tunables (#2691 P2,
// plan §5.9). The `provider <name>` block is a repeatable named instance
// (credentials configured once, referenced by per-interface bindings). The
// backend enum is validated (rfc2136 live; dyndns2/cloudflare/route53/generic
// reserved for P3); credentials stay free-form (a valid base64 secret / host
// is not rejected at commit — the live backend is warn-validated at commit and
// fail-open at runtime). forced-refresh / error-backoff-max accept a Go
// duration ("24h") or a bare-seconds integer.
func ddnsServicesSchema() *schemaNode {
	return &schemaNode{desc: "Dynamic DNS provider catalog + engine tunables (Surface A, #2691)", children: map[string]*schemaNode{
		"provider": {desc: "Named DDNS provider", args: 1, placeholder: "<provider-name>", children: map[string]*schemaNode{
			"backend": {
				desc:          "DNS-update backend (rfc2136/dyndns2/duckdns/cloudflare/route53/generic)",
				args:          1,
				valueType:     ValueEnumOf,
				valueDesc:     "Update backend (rfc2136 [live] | dyndns2 | duckdns | cloudflare | route53 | generic)",
				valueExamples: []string{"rfc2136"},
				validator:     ValidateEnum([]string{"rfc2136", "dyndns2", "duckdns", "cloudflare", "route53", "generic"}),
				children:      nil,
			},
			"update-server":         {desc: "Authoritative DNS target for RFC 2136 updates (host[:port])", args: 1, placeholder: "<host[:port]>", children: nil},
			"tsig-key":              {desc: "TSIG key name for authenticated updates", args: 1, placeholder: "<key-name>", children: nil},
			"tsig-algorithm":        {desc: "TSIG algorithm (e.g. hmac-sha256)", args: 1, placeholder: "<algorithm>", children: nil},
			"tsig-secret":           {desc: "TSIG shared secret (sensitive; redacted in show output)", args: 1, placeholder: "<secret>", children: nil},
			"source-address":        {desc: "Source address to bind the UPDATE socket to (#2665)", args: 1, placeholder: "<ip>", children: nil},
			"destination-interface": {desc: "Egress interface to pin the UPDATE to (SO_BINDTODEVICE, #2665)", args: 1, placeholder: "<interface>", children: nil},
			"routing-instance":      {desc: "Routing instance / VRF the UPDATE egresses from (#2665)", args: 1, placeholder: "<instance>", children: nil},
			// HTTP-provider leaves (#2691 P3).
			"server":            {desc: "dyndns2 update endpoint host or base URL (default: built-in for the named provider)", args: 1, placeholder: "<host|url>", children: nil},
			"username":          {desc: "HTTP Basic-auth username (dyndns2 / generic)", args: 1, placeholder: "<username>", children: nil},
			"password":          {desc: "HTTP Basic-auth password (sensitive; redacted in show output)", args: 1, placeholder: "<secret>", children: nil},
			"url-template":      {desc: "generic backend update URL template (%h host, %i IP, %u user, %p pass, %% literal)", args: 1, placeholder: "<url-template>", children: nil},
			"ok-response":       {desc: "generic backend success-substring matcher (default: good/nochg/ok/true/updated)", args: 1, placeholder: "<substring>", children: nil},
			"api-token":         {desc: "Cloudflare / DuckDNS API token (sensitive; redacted in show output)", args: 1, placeholder: "<secret>", children: nil},
			"zone":              {desc: "Cloudflare DNS zone name the record lives in (e.g. example.net)", args: 1, placeholder: "<zone>", children: nil},
			"aws-access-key":    {desc: "Route 53 AWS access-key id (SigV4)", args: 1, placeholder: "<access-key-id>", children: nil},
			"aws-secret-key":    {desc: "Route 53 AWS secret access key (sensitive; redacted in show output)", args: 1, placeholder: "<secret>", children: nil},
			"aws-region":        {desc: "Route 53 AWS region for SigV4 signing (default: us-east-1)", args: 1, placeholder: "<region>", children: nil},
			"hosted-zone-id":    {desc: "Route 53 hosted-zone id (e.g. Z123456ABCDEF)", args: 1, placeholder: "<zone-id>", children: nil},
			"checkip-url":       {desc: "optional external check-IP URL for behind-NAT address detection (opt-in, #2691 P3)", args: 1, placeholder: "<url>", children: nil},
			"checkip-allowlist": {desc: "comma/space-separated bogus addresses to ignore in a check-IP response (e.g. 1.1.1.1)", args: 1, placeholder: "<addr-list>", children: nil},
		}},
		"forced-refresh":    {desc: "Wire-update floor for an unchanged address (duration, e.g. 24h, or seconds; default 24h)", args: 1, placeholder: "<duration>", children: nil},
		"error-backoff-max": {desc: "Cap for the per-scope error backoff (duration, e.g. 1h, or seconds; default 1h)", args: 1, placeholder: "<duration>", children: nil},
	}}
}

// dhcpExpiredLeasesSchema returns the typed-leaf schema for the #1387
// stale-lease-cleanup slice (Path S): the per-family
// `expired-leases-processing` reclamation block, shared by
// dhcp-local-server and dhcpv6-local-server. Returned fresh per call so
// the two parents do not alias a mutable map (same pattern as
// dhcpDynamicDNSSchema / dhcpStaticBindingSchema).
//
// Floor split (SMR MAJOR-3, fail-safe default): the three TIMERS
// (reclaim/flush/hold) use ValidateIntegerMin(1) because a 0 some Kea
// versions reject would take DHCP DOWN on the fail-closed restart; the
// two CAP knobs (max-leases, max-time) use ValidateIntegerMin(0) because
// Kea documents 0 = unlimited there (a value the model tracks distinctly
// from unset — invariant H2), and unwarned-cycles uses Min(0). Kea has
// no documented hard upper bound on these knobs, so min-only validation
// is correct (no schema-only cap, per the docs/config-schema.md range
// policy).
func dhcpExpiredLeasesSchema() *schemaNode {
	return &schemaNode{desc: "Kea expired-lease reclamation policy (#1387)", children: map[string]*schemaNode{
		"enable": {desc: "Enable expired-lease reclamation tuning", children: nil},
		"reclaim-timer": {
			desc:          "Seconds between reclamation cycles (reclaim-timer-wait-time)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Seconds (>= 1)",
			valueExamples: []string{"10"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"flush-timer": {
			desc:          "Seconds between reclaimed-lease flush passes (flush-reclaimed-timer-wait-time)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Seconds (>= 1)",
			valueExamples: []string{"25"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"hold-time": {
			desc:          "Seconds a reclaimed lease is held before removal (hold-reclaimed-time)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Seconds (>= 1)",
			valueExamples: []string{"600"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"max-leases": {
			desc:          "Maximum leases reclaimed per cycle, 0 = unlimited (max-reclaim-leases)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Leases per cycle (>= 0; 0 = unlimited)",
			valueExamples: []string{"100", "0"},
			validator:     ValidateIntegerMin(0),
			children:      nil,
		},
		"max-time": {
			desc:          "Max milliseconds spent reclaiming per cycle, 0 = unlimited (max-reclaim-time)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Milliseconds (>= 0; 0 = unlimited)",
			valueExamples: []string{"250", "0"},
			validator:     ValidateIntegerMin(0),
			children:      nil,
		},
		"unwarned-cycles": {
			desc:          "Consecutive capped cycles before Kea warns (unwarned-reclaim-cycles)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Cycles (>= 0)",
			valueExamples: []string{"5"},
			validator:     ValidateIntegerMin(0),
			children:      nil,
		},
	}}
}

// dhcpLocalServerGroupSchema returns the `group <name>` subtree shared by
// `system services dhcp-local-server` and `system services
// dhcpv6-local-server`, fresh per call so the two families do not alias a
// mutable map (same pattern as dhcpDynamicDNSSchema /
// dhcpStaticBindingSchema). fam is "DHCP" / "DHCPv6", used only in the
// completion descriptions.
//
// SINGLE-SOURCED ON PURPOSE (#6696). The two families previously carried
// two independent literal copies of this subtree, and a divergence between
// them is always a bug: `interface` and `pool dns-server` mean the same
// thing in both, and the compiler (compileDHCPLocalServer) is ONE function
// that runs for both with an isV6 flag. One definition makes drift
// unrepresentable rather than merely tested-against.
//
// #6696 — WHY `interface` AND `dns-server` ARE MODELLED AT ALL. Both were
// unmodelled, so the grammar said nothing about how many tokens they take
// and the compiler read one value with nodeVal. A bracketed list —
// `interface [ ge-0/0/0.0 ge-0/0/1.0 ]`, the ordinary way to write a
// multi-segment group — collapses onto ONE leaf's Keys (the #2419
// contract), so everything past slot 0 was silently DROPPED: the group
// served only its first interface and the second segment got no leases at
// all, and a pool offered one resolver where two were configured. It
// reproduces identically on the strict commit path and the tolerant load
// path — the failing axis is BRACKETED-vs-repeated-leaf, not
// strict-vs-tolerant.
//
//   - `multi: true` states that the trailing tokens are VALUES, which is
//     what lets the compiler read the whole tail instead of guessing.
//   - `valueList: true` on `interface` is the #3872 static-route `next-hop`
//     precedent, and it is load-bearing: it absorbs a trailing token that is
//     neither a sibling NOR a known child (the bracket list) while STILL
//     descending into the container when the next token names a known child
//     (a per-interface MODIFIER). Without it the modifier keyword would be
//     absorbed as an interface NAME and shipped to Kea's
//     interfaces-config.interfaces, where a name no device answers to takes
//     the whole DHCP server down.
//   - the per-interface modifier keywords are therefore modelled — not
//     because xpf implements them (it does not, and did not before this
//     change either: the token was silently dropped by the single-value
//     read) but because the grammar has to be able to PARK them somewhere
//     other than the value list. They are parsed and ignored, exactly as
//     before.
//   - the typed validators (ValidateInterfaceName / ValidateIPAddress) are
//     the "widened read needs a widened validator" half: every element of a
//     widened list is now checked, not just slot 0. They run on the strict
//     commit / commit-check path only (schemaValidateExpandedTreeForNode,
//     pkg/configstore), so an already-persisted config still boots (#1960).
func dhcpLocalServerGroupSchema(fam string) *schemaNode {
	return &schemaNode{
		desc:        fam + " group",
		args:        1,
		placeholder: "<group-name>",
		children: map[string]*schemaNode{
			"interface": {
				desc:             "Interface this group serves (repeatable; accepts a bracketed list)",
				args:             1,
				multi:            true,
				valueList:        true,
				placeholder:      "<interface>",
				keyValueDesc:     "Interface name, optionally unit-qualified",
				keyValueExamples: []string{"ge-0/0/1.0", "reth0.80"},
				// keyValidator, NOT validator: this node declares CHILDREN
				// (the per-interface modifiers), so its values ride on the
				// identity KEY slot, and the #5726 valueList+keyValidator arm
				// of the schema walk is what validates EVERY packed value
				// rather than only the first — the same arm the static-route
				// `next-hop [ gw1 gw2 ]` list relies on. A plain `validator`
				// is only consulted for a childless leaf and would have left
				// every element of a widened list unchecked.
				keyValidator: ValidateInterfaceName,
				// Junos per-interface options. xpf parses and IGNORES every
				// one of them; they are modelled so valueList can descend
				// into them instead of absorbing the keyword as an interface
				// name. See the function comment.
				children: map[string]*schemaNode{
					"access-profile":        {desc: "Per-interface access profile (parsed, not implemented)", args: 1, placeholder: "<profile>", children: nil},
					"client-discover-match": {desc: "Client discover match option (parsed, not implemented)", args: 1, placeholder: "<match>", children: nil},
					"dynamic-profile":       {desc: "Per-interface dynamic profile (parsed, not implemented)", args: 1, placeholder: "<profile>", children: nil},
					"exclude":               {desc: "Exclude this interface from the group (parsed, not implemented)", children: nil},
					"overrides":             {desc: "Per-interface overrides (parsed, not implemented)", children: nil},
					"service-profile":       {desc: "Per-interface service profile (parsed, not implemented)", args: 1, placeholder: "<profile>", children: nil},
					"short-cycle-protection-lockout-max-time": {desc: "Short-cycle lockout max time (parsed, not implemented)", args: 1, placeholder: "<seconds>", children: nil},
					"short-cycle-protection-lockout-min-time": {desc: "Short-cycle lockout min time (parsed, not implemented)", args: 1, placeholder: "<seconds>", children: nil},
					"trace":          {desc: "Per-interface tracing (parsed, not implemented)", children: nil},
					"upgrade-server": {desc: "Per-interface upgrade server (parsed, not implemented)", args: 1, placeholder: "<address>", children: nil},
				},
			},
			"pool": {desc: "Address pool", args: 1, placeholder: "<pool-name>", children: map[string]*schemaNode{
				"dns-server": {
					desc:          "DNS resolver offered to clients of this pool (repeatable; accepts a bracketed list)",
					args:          1,
					multi:         true,
					placeholder:   "<address>",
					valueType:     ValueIPAddress,
					valueDesc:     "Resolver IP address",
					valueExamples: []string{"192.0.2.53", "2001:db8::53"},
					validator:     ValidateIPAddress,
					children:      nil,
				},
				"static-binding": dhcpStaticBindingSchema(),
			}},
		},
	}
}

// dhcpStaticBindingSchema returns the typed-leaf schema for a #2243
// DHCP-server static (fixed/reserved) host binding, used under both
// dhcp-local-server and dhcpv6-local-server `group <g> pool <p>`. The
// instance key is the client hardware address (MAC), validated by
// ValidateMAC; fixed-address is a typed IP slot. The address-within-subnet,
// duplicate-MAC, and duplicate-address checks need the compiled pool
// (subnet), so they live in validateDHCPStaticBindingsStrict, not here.
// Returned fresh per call so the two parents do not share a mutable map.
func dhcpStaticBindingSchema() *schemaNode {
	return &schemaNode{
		desc:             "Fixed/reserved address binding for a client MAC (#2243)",
		args:             1,
		placeholder:      "<mac-address>",
		keyValueType:     ValueMAC,
		keyValueDesc:     "Client hardware (MAC) address (xx:xx:xx:xx:xx:xx)",
		closedWorld:      true, // #9265
		keyValueExamples: []string{"00:11:22:33:44:55"},
		keyValidator:     ValidateMAC,
		children: map[string]*schemaNode{
			"fixed-address": {
				desc:          "Reserved IP the matching client always receives (must be inside the pool subnet)",
				args:          1,
				valueType:     ValueIPAddress,
				valueDesc:     "Fixed IP address (v4 or v6) within the enclosing pool subnet",
				valueExamples: []string{"10.0.1.50", "2001:db8::50"},
				validator:     ValidateIPAddress,
				children:      nil,
			},
			"host-name": {
				desc:        "Optional reservation hostname (Kea reservation hostname)",
				args:        1,
				placeholder: "<host-name>",
				children:    nil,
			},
		},
	}
}

var schemaSNMP = &schemaNode{desc: "SNMP configuration", children: map[string]*schemaNode{
	"community": {desc: "SNMP community", args: 1, placeholder: "<community-name>", children: map[string]*schemaNode{
		"authorization": {
			desc:          "Authorization level",
			args:          1,
			placeholder:   "<level>",
			valueType:     ValueEnumOf,
			valueDesc:     "Access level granted to the community (read-only | read-write)",
			valueExamples: []string{"read-only", "read-write"},
			validator:     ValidateEnum([]string{"read-only", "read-write"}),
			children:      nil,
		},
		// #4289: source-IP allowlist. `clients <prefix> [restrict]` — multi so a
		// bracketed list / repeated set lines collapse onto the leaf; the
		// trailing optional `restrict` deny modifier rides on the same run and
		// is paired to its prefix by parseSNMPClients.
		"clients": {desc: "Source-IP allowlist for this community (<prefix> [restrict])", args: 1, multi: true, placeholder: "<prefix>", children: nil},
		// #9416: the NAMED spelling of the same source restriction. Junos
		// expresses one allowlist two ways -- inline `clients`, or a reusable
		// `snmp client-list <name>` referenced from here -- and only the inline
		// one was modelled, so the named form committed clean, compiled to
		// nothing, and left the community ALLOW-ALL. Five prior fixes (#4289,
		// #5472, #5833, #5898, #8778) all landed on the inline sibling; every
		// one of them assumed the restriction is spelled inline.
		"client-list-name": {desc: "Name of an `snmp client-list` whose prefixes restrict this community", args: 1, placeholder: "<client-list-name>", children: nil},
		// #9416, the SIXTH spelling, found by censusing the family rather than
		// fixing the fifth. `community <c> routing-instance <ri> { clients ... }`
		// / `{ client-list-name ... }` is the per-routing-instance form of the
		// same control, and it was measured fail-open exactly like the named
		// list. xpf's SNMP agent has no routing-instance awareness, so the
		// SCOPING is not enforced (compileSNMP emits an advisory saying so) --
		// but the source restriction inside it IS applied to the community,
		// because leaving it out means allow-all.
		// closedWorld (#9091/#4313): this body is LEAF-COMPLETE — Junos puts
		// exactly `clients` and `client-list-name` under a community's
		// routing-instance — and every keyword it could otherwise absorb is a
		// SOURCE RESTRICTION. An unmodelled keyword here would commit clean and
		// leave the community answering every source, which is the defect this
		// whole change is about; a typo must be told to the operator instead.
		"routing-instance": {desc: "Routing-instance scope for this community (the scoping is NOT enforced; its source restriction IS applied)", args: 1, placeholder: "<instance-name>", closedWorld: true, children: map[string]*schemaNode{
			"clients":          {desc: "Source-IP allowlist for this community in this routing instance (<prefix> [restrict])", args: 1, multi: true, placeholder: "<prefix>", children: nil},
			"client-list-name": {desc: "Name of an `snmp client-list` whose prefixes restrict this community in this routing instance", args: 1, placeholder: "<client-list-name>", children: nil},
		}},
	}},
	// #9416: `snmp client-list <name> { <prefix> [restrict]; }` -- a reusable
	// named source-IP allowlist that one or more communities reference by name.
	// `multi: true` so the flat spelling `set snmp client-list trusted 10.0.0.0/8`
	// collapses its prefixes onto the node's Keys, matching how `clients` is
	// declared; the braced body lands on Children. parseSNMPClientListPrefixes
	// reads BOTH shapes (the #2419 dual-shape class).
	"client-list": {desc: "Named source-IP client list (<prefix> [restrict])", args: 1, multi: true, placeholder: "<client-list-name>", children: nil},
	// packedStatements (#8768): compileSNMP reads `targets` and `version` as
	// separate statements, and the packed spelling
	// `trap-group tg1 targets 10.0.0.1 version v2;` used to collapse both into
	// one node, silently losing the version. Measured: with the split the packed
	// and braced spellings compile identically.
	"trap-group": {desc: "Trap group", args: 1, placeholder: "<group-name>", packedStatements: true, children: map[string]*schemaNode{
		"targets": {
			desc:        "Trap target host (IP address or FQDN, optional :port)",
			args:        1,
			multi:       true,
			placeholder: "<target>",
			children:    nil,
		},
		"version": {
			desc:          "SNMP version for this trap group",
			args:          1,
			placeholder:   "<version>",
			valueType:     ValueEnumOf,
			valueDesc:     "Trap protocol version (v1 | v2 | all)",
			valueExamples: []string{"v1", "v2", "all"},
			validator:     ValidateEnum([]string{"v1", "v2", "all"}),
			children:      nil,
		},
		"categories": {desc: "Trap categories to send to this group", args: 1, multi: true, placeholder: "<category>", children: nil},
	}},
	"v3": {desc: "SNMPv3", children: map[string]*schemaNode{
		"usm": {desc: "USM", children: map[string]*schemaNode{
			"local-engine": {desc: "Local engine", children: map[string]*schemaNode{
				"user": {desc: "User name", args: 1, placeholder: "<user-name>", children: map[string]*schemaNode{
					"authentication-md5":    {desc: "MD5 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
					"authentication-sha":    {desc: "SHA authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
					"authentication-sha256": {desc: "SHA256 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
					"privacy-des":           {desc: "DES privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
					"privacy-aes128":        {desc: "AES128 privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
				}},
			}},
		}},
	}},
}}

var schemaEventOptions = &schemaNode{desc: "Event policies for automated configuration changes", children: map[string]*schemaNode{
	"policy": {desc: "Event policy", args: 1, placeholder: "<policy-name>", children: map[string]*schemaNode{
		"events": {desc: "Events that trigger this policy", children: nil},
		// within/trigger numerics are strict-validated at commit by
		// validateEventOptionsWithinAST (#3751), not a typed leaf: the
		// constraint spans the whole clause (seconds + trigger keyword/count +
		// on/until mutual exclusion). within is 1..86400 s; trigger count is
		// 1..1000000. A typo previously coerced to 0 and always-fired.
		"within": {desc: "Time window for trigger evaluation (1..86400 seconds)", args: 1, placeholder: "<seconds>", children: map[string]*schemaNode{
			"trigger": {desc: "Trigger condition: on|until <count> (exactly one; count 1..1000000)", children: nil},
		}},
		"attributes-match": {desc: "Match event attributes (<event>.<attribute> matches <value>)", children: nil},
		"then": {desc: "Actions when the policy triggers", children: map[string]*schemaNode{
			"change-configuration": {desc: "Apply configuration changes", children: map[string]*schemaNode{
				"commands": {desc: "Configuration commands to apply (set/delete)", children: nil},
			}},
		}},
	}},
}}
