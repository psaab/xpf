package config

// ValueType classifies the value a typed-leaf node accepts. #1319.
//
// The zero value, ValueAny, is the legacy behaviour: any string is accepted
// and no schema-time validation runs. Specifying a non-zero ValueType opts
// the leaf in to:
//   - `?` completion surfacing ValueDesc + ValueExamples for the value slot;
//   - SchemaValidate invoking the leaf's Validator at commit check, so
//     garbage like `transmit-rate asd` fails loud at commit time instead of
//     silently zeroing out the rate inside the compiler.
//
// ValueType lives in pkg/config (not pkg/cmdtree) so the config-grammar
// schema (setSchema, the live config-mode `set` completion + validation
// tree) can carry typed-leaf metadata directly. pkg/cmdtree already imports
// pkg/config, so the type cannot live in cmdtree without an import cycle;
// cmdtree re-exports it via `type ValueType = config.ValueType` aliases for
// its operational-tree leaves. See #1319 plan §5 ("Type ownership").
//
// Add new types here only when we're prepared to wire validators for every
// leaf that adopts them — IP/CIDR/MAC/duration are deliberately deferred
// (see issue #1319) until their subsystem PRs land.
type ValueType int

const (
	// ValueAny is the legacy default: any string accepted, no validation.
	ValueAny ValueType = iota
	// ValueRate is a Junos bandwidth value (bits/sec) with k/m/g suffix.
	// Examples: "100k", "10m", "1g". Accepts plain integers.
	ValueRate
	// ValueByteSize is a byte-count value with k/m/g suffix.
	// Examples: "16k", "1m", "256m".
	ValueByteSize
	// ValueByteSizeOrPercent is a scheduler buffer size: byte-count with
	// k/m/g suffix, or percent with an explicit % suffix.
	ValueByteSizeOrPercent
	// ValuePercent is a percent value in the range [0, 100] (no suffix).
	ValuePercent
	// ValueRateOrPercent is a CoS scheduler/shaper rate expressed EITHER as a
	// bandwidth with k/m/g suffix (10m), or the Junos keyword forms
	// `percent <n>` / `remainder`. The heterogeneous tail is validated by the
	// leaf's tailValidator, not a single-token validator; this type only
	// drives the `?` completion placeholder. #4228 Gap 2.
	ValueRateOrPercent
	// ValueInteger is a bare integer. Range is enforced by the leaf's
	// Validator (callers use ValidateInteger(min,max) to bound it).
	ValueInteger
	// ValueIdentifier is a bare Junos identifier (no spaces, no quotes).
	ValueIdentifier
	// ValueEnumOf is one of a fixed set of names. The allowed set lives
	// in the leaf's Validator closure (ValidateEnum).
	ValueEnumOf
	// ValueBool is "true" or "false".
	ValueBool
	// ValueIPAddress is an IP address without a prefix length. The
	// accepted family (v4, v6, or either) is enforced by the leaf's
	// validator (ValidateIPAddress / ValidateIPv4Address). #1319 PR 3.
	ValueIPAddress
	// ValueCIDR is an IP address WITH a prefix length (e.g.
	// 10.0.1.10/24, 2001:db8::1/64). The accepted family is enforced by
	// the leaf's validator (ValidateIPv4CIDR / ValidateIPv6CIDR).
	ValueCIDR
	// ValueCryptHash is a crypt(3) modular password hash (e.g.
	// $6$salt$checksum) or an explicit lock sentinel (*, !, !!). The
	// leaf's validator (ValidateCryptHash) rejects plaintext at commit
	// check so an operator cannot paste cleartext into an
	// encrypted-password directive. #1944.
	ValueCryptHash
	// ValuePCIAddr is a PCI bus address (DDDD:BB:DD.F, e.g.
	// 0000:09:00.0), the #1956 device-map primary identity key. Validated
	// by ValidatePCIAddr.
	ValuePCIAddr
	// ValueMAC is a MAC address (xx:xx:xx:xx:xx:xx), the #1956 device-map
	// permanent-MAC fallback identity key. Validated by ValidateMAC.
	ValueMAC
	// ValueDHGroup is an IKE/IPsec Diffie-Hellman group as either a bare
	// positive integer ("14") or the Junos "group<N>" spelling
	// ("group14"). Both spellings compile; validated by ValidateDHGroup.
	ValueDHGroup
	// ValueHostname is a DNS hostname / FQDN whose published form must equal
	// the operator's intent: LDH labels (letters, digits, hyphens) joined by
	// dots, with an optional trailing dot. The shared DNS shape and length
	// rules are enforced by each leaf's validator; for example, DDNS uses
	// ValidateDDNSHostname while system host-name uses ValidateSystemHostname.
	ValueHostname
	// ValueTimeOfDay is a Junos scheduler time-of-day in HH:MM:SS 24-hour
	// form (e.g. 09:00:00). Validated by ValidateTimeOfDay so an
	// unparseable start-time/stop-time is rejected at commit instead of
	// silently zeroing the scheduler window (#3849 fail-closed).
	ValueTimeOfDay
	// ValueDate is a Junos scheduler calendar date in YYYY-MM-DD form
	// (e.g. 2026-03-01). Validated by ValidateDate.
	ValueDate
	// ValueTimeZone is an IANA tz-database / zoneinfo name (e.g. UTC,
	// America/Los_Angeles, Etc/GMT+5). It is rendered into the
	// /etc/localtime symlink target, so ValidateTimeZone rejects a `..`
	// component / absolute path / space at commit check to keep the target
	// inside the zoneinfo root (#5011).
	ValueTimeZone
	// ValueSecureTunnelIf is an IPsec route-based VPN bind-interface: a
	// canonical secure-tunnel interface st<N> or st<N>.<unit> (e.g. st0,
	// st0.1). Validated by ValidateSecureTunnelBindInterface — any other
	// name resolves to no XFRM device (XFRMIfNameAndID if_id 0), so the VPN
	// commits but silently carries no traffic; the name is rejected at
	// commit check (#5297).
	ValueSecureTunnelIf
	// ValueUnixSocketPath is an absolute filesystem path a Unix-domain
	// socket is bound at (`system dataplane control-socket`). Validated by
	// ValidateUnixSocketPath: absolute, no `.`/`..`/empty component, within
	// the 107-octet AF_UNIX sun_path limit. The path is handed to the
	// dataplane's stale-socket unlink at every bring-up, so a traversal or a
	// relative path is rejected at commit rather than resolved at runtime
	// against a working directory the operator never named (#5839).
	ValueUnixSocketPath
	// ValueInterfaceName is a Junos or kernel interface name, optionally with
	// a unit suffix: `ge-0/0/0`, `ge-0-0-0.0`, `reth0.50`, `st0.1`, `fab0`,
	// `irb`, `enp5s0`. Validated by ValidateRIPNeighborInterface.
	//
	// It exists because a validator ALONE does not run: the schema walk's
	// typed-leaf branch is a CONJUNCTION, `isTypedLeaf() && validator != nil`,
	// and isTypedLeaf() is `valueType != ValueAny`. A leaf carrying only a
	// validator is silently never checked -- which is how #9206's absorbed
	// tokens reached the neighbour list past a validator that had been wired
	// on but not typed.
	ValueInterfaceName
)

// Placeholder returns the angle-bracket placeholder name shown in `?`
// completion for an unfilled value slot of this type.
func (v ValueType) Placeholder() string {
	switch v {
	case ValueRate:
		return "<rate>"
	case ValueByteSize:
		return "<bytes>"
	case ValueByteSizeOrPercent:
		return "<bytes|percent>"
	case ValuePercent:
		return "<percent>"
	case ValueRateOrPercent:
		return "<rate|percent|remainder>"
	case ValueInteger:
		return "<integer>"
	case ValueIdentifier:
		return "<name>"
	case ValueEnumOf:
		return "<value>"
	case ValueBool:
		return "<true|false>"
	case ValueIPAddress:
		return "<address>"
	case ValueCIDR:
		return "<address/prefix-length>"
	case ValueCryptHash:
		return "<crypt-hash>"
	case ValuePCIAddr:
		return "<pci-address>"
	case ValueMAC:
		return "<mac-address>"
	case ValueDHGroup:
		return "<dh-group>"
	case ValueHostname:
		return "<fqdn>"
	case ValueTimeOfDay:
		return "<HH:MM:SS>"
	case ValueDate:
		return "<YYYY-MM-DD>"
	case ValueTimeZone:
		return "<timezone>"
	case ValueInterfaceName:
		return "<interface-name>"
	case ValueSecureTunnelIf:
		return "<st-interface>"
	case ValueUnixSocketPath:
		return "<socket-path>"
	}
	return ""
}
