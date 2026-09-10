// Package nat holds control-plane NAT domain queries that are shared,
// unmodified, across every operator surface (CLI, gRPC, REST).
//
// deterministic.go is the canonical deterministic source-NAT (CGNAT /
// NAPT64) forward and reverse mapping lookup behind:
//
//   - CLI  `show security nat source deterministic-nat internal-host <ip>`
//     and `... nat-ip <ip> nat-port <n>`
//   - gRPC `GetNATDeterministic`
//   - REST `GET /api/v1/security/nat/deterministic`
//
// All three consume the SAME typed result computed here so a CLI answer
// can never drift from the API answer (#5794 design invariant 1).
//
// The mapping is a pure function of the LAST-APPLIED NAT configuration
// (never the candidate / desired-but-unapplied config — invariant 3) plus
// the query tuple, so it needs no dataplane round-trip and adds no
// persistent reverse index to the packet path (invariant 7). It mirrors
// the Rust dataplane allocator exactly — userspace-dp/src/nat/allocator.rs
// deterministic_indices_v4 / reverse_deterministic_v4 and the _v6 twins —
// and is pinned to it by cross-language golden vectors
// (deterministic_test.go) and a Go-side parity test that cross-checks the
// parameter derivation against the shipped wire-field builders
// (pkg/dataplane/userspace, nat_deterministic_parity_test.go).
package nat

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// Mode classifies the deterministic pool's subscriber family, matching the
// Junos deterministic-NAT modes and the dataplane DeterministicMode wire
// field.
type Mode uint8

const (
	// ModeNone is a non-deterministic (round-robin) pool.
	ModeNone Mode = 0
	// ModeV4 is IPv4 deterministic source NAT (Junos mode 1).
	ModeV4 Mode = 1
	// ModeV6 is IPv6-subscriber deterministic NAPT64 (Junos mode 2).
	ModeV6 Mode = 2
)

// String renders the mode for operator output.
func (m Mode) String() string {
	switch m {
	case ModeV4:
		return "ipv4-source-nat"
	case ModeV6:
		return "ipv6-napt64"
	default:
		return "none"
	}
}

// Stable, machine-readable error codes (invariant 10). Every surface
// (CLI / gRPC / REST) reports the SAME code so tooling can branch on it.
const (
	// ErrCodeNoAppliedView: the dataplane has applied no NAT config yet
	// (helper not running or first apply not landed). The query fails
	// closed rather than computing from a candidate config.
	ErrCodeNoAppliedView = "no-applied-view"
	// ErrCodeUnknownPool: the named pool does not exist in the applied
	// config.
	ErrCodeUnknownPool = "unknown-pool"
	// ErrCodeNotDeterministic: the pool exists but carries no valid
	// deterministic block-allocation configuration.
	ErrCodeNotDeterministic = "not-deterministic"
	// ErrCodeMalformedInput: an address/port argument could not be parsed
	// or is the wrong family for the pool's mode.
	ErrCodeMalformedInput = "malformed-input"
	// ErrCodeOutOfRange: a forward subscriber falls outside the pool's
	// configured subscriber space.
	ErrCodeOutOfRange = "out-of-range"
	// ErrCodeAmbiguousPool: no pool was selected and more than one
	// deterministic pool contains the queried tuple. Never a first-match.
	ErrCodeAmbiguousPool = "ambiguous-pool"
	// ErrCodeNotFound: a reverse tuple does not fall in any deterministic
	// pool's translated space.
	ErrCodeNotFound = "not-found"
)

// LookupError carries a stable machine code plus a human detail string.
type LookupError struct {
	Code   string
	Detail string
}

func (e *LookupError) Error() string {
	if e == nil {
		return ""
	}
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func lerrf(code, format string, a ...any) *LookupError {
	return &LookupError{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// AppliedView is the last-applied NAT configuration + generation the query
// runs against. Callers build it from the userspace manager's
// AppliedNATView() (config + AppliedGeneration + Available); it reads only
// cached in-memory state, no control-socket I/O.
type AppliedView struct {
	Config     *config.Config
	Generation uint64
	Available  bool
}

// ForwardResult is a subscriber -> translated deterministic mapping.
type ForwardResult struct {
	Pool              string
	Mode              Mode
	InternalHost      string // normalized queried subscriber
	ExternalIP        string // translated external IPv4
	PortLow           uint16 // inclusive port-block low
	PortHigh          uint16 // inclusive port-block high
	BlockSize         uint16
	BlockIndex        uint32
	AppliedGeneration uint64
}

// ReverseResult is a translated -> subscriber deterministic mapping.
type ReverseResult struct {
	Pool         string
	Mode         Mode
	ExternalIP   string // translated external IPv4 (echoed)
	NATPort      uint16 // translated port (echoed)
	InternalHost string // recovered subscriber (IPv4, or IPv6 prefix BASE)
	// InternalPrefixLen is the prefix length of the DETERMINISTIC UNIT that
	// InternalHost names, or 0 in IPv4 mode where the value is an exact host
	// (#9070).
	//
	// It is NOT the configured pool prefix. `detParamsForPool` reports that
	// separately as 32 or 64; this is the unit the reverse lookup can actually
	// resolve to, which is the configured prefix PLUS the 32-bit subscriber
	// word the lookup reconstructs: wordOffset 4 -> /64, wordOffset 8 -> /96.
	// The two answer similar-sounding questions and are never equal, so a
	// consumer that reused the pool prefix here would render a /64 for a value
	// that is really a /96 -- confidently wrong rather than merely ambiguous.
	InternalPrefixLen int
	PortLow           uint16 // inclusive low of the block containing NATPort
	PortHigh          uint16 // inclusive high of that block
	BlockSize         uint16
	BlockIndex        uint32
	AppliedGeneration uint64
}

// nat64PortLow / nat64PortHigh mirror the FIXED NAT64 translated-port range
// the Rust per-prefix allocator uses (userspace-dp/src/nat64.rs). Mode-2
// block boundaries are computed against THIS range, not the pool's own
// `port` range (which the NAT64 allocator ignores).
const (
	nat64PortLow  = 1024
	nat64PortHigh = 65535
	// maxPoolPrefixHosts mirrors the Rust MAX_POOL_PREFIX_HOSTS cap on
	// enumerating a pool CIDR into individual external addresses.
	maxPoolPrefixHosts = 65536
)

// detParams is the resolved deterministic block-allocation parameters for
// one pool, mirroring the Rust DeterministicV4 / DeterministicV6.
type detParams struct {
	mode        Mode
	blockSize   uint16
	blocksPerIP uint16
	portLow     uint16
	poolV4      []net.IP // ordered 4-byte external addresses (forward indexes this)
	hostCount   uint32

	// mode 1 (IPv4 subscriber):
	hostBaseV4 uint32 // host-order numeric base (== Rust u32::from(Ipv4Addr))

	// mode 2 (IPv6 subscriber / NAPT64):
	hostBaseV6 [16]byte
	wordOffset int // 4 for a /32 subscriber prefix, 8 for a /64
}

// LookupForward resolves a subscriber -> translated deterministic mapping
// against the applied view. poolName may be "" to search every
// deterministic pool; when omitted, more than one matching pool returns
// ErrCodeAmbiguousPool (never a first-match, invariant 6).
func LookupForward(view AppliedView, poolName, host string) (*ForwardResult, *LookupError) {
	cfg, gen, lerr := appliedConfig(view)
	if lerr != nil {
		return nil, lerr
	}
	trimmed := strings.TrimSpace(host)
	// Classify the query family with the colon-strict Go/Rust-parity SSOT, NOT
	// net.IP.To4() — Go folds an IPv4-mapped literal (::ffff:100.64.0.5) to a
	// 4-byte form, so a To4() gate would accept it into a mode-1 (IPv4) pool and
	// fabricate a subscriber the Rust dataplane (which only maps IpAddr::V4 in
	// mode 1 and passes an Ipv6Addr to mode 2) never translates.
	fam := config.NATAddrFamily(trimmed)
	if fam == "" {
		return nil, lerrf(ErrCodeMalformedInput, "unparseable subscriber address %q", host)
	}
	ip := net.ParseIP(trimmed)
	nat64Refs := nat64ReferencedPools(cfg)

	if poolName != "" {
		pool, ok := cfg.Security.NAT.SourcePools[poolName]
		if !ok || pool == nil {
			return nil, lerrf(ErrCodeUnknownPool, "no source NAT pool named %q in the applied configuration", poolName)
		}
		p, perr := poolParams(pool, nat64Refs[poolName])
		if perr != nil {
			return nil, perr
		}
		return lookupForwardInPool(p, poolName, ip, fam, gen)
	}

	var results []*ForwardResult
	var matched []string
	var lastNonMatch *LookupError
	for _, name := range sortedDeterministicPoolNames(cfg) {
		p, perr := poolParams(cfg.Security.NAT.SourcePools[name], nat64Refs[name])
		if perr != nil {
			continue
		}
		r, rerr := lookupForwardInPool(p, name, ip, fam, gen)
		if rerr != nil {
			lastNonMatch = rerr
			continue
		}
		results = append(results, r)
		matched = append(matched, name)
	}
	switch len(results) {
	case 1:
		return results[0], nil
	case 0:
		if lastNonMatch != nil && lastNonMatch.Code == ErrCodeMalformedInput {
			return nil, lastNonMatch
		}
		return nil, lerrf(ErrCodeOutOfRange, "subscriber %s is not in the subscriber range of any deterministic pool", host)
	default:
		return nil, lerrf(ErrCodeAmbiguousPool,
			"subscriber %s matches multiple deterministic pools (%s); select one with `pool`", host, strings.Join(matched, ", "))
	}
}

// LookupReverse resolves a translated (external IPv4, port) -> subscriber
// deterministic mapping against the applied view. poolName may be "" to
// search every deterministic pool; when omitted, a tuple present in more
// than one pool returns ErrCodeAmbiguousPool (never a first-match).
func LookupReverse(view AppliedView, poolName, natIP string, natPort uint16) (*ReverseResult, *LookupError) {
	cfg, gen, lerr := appliedConfig(view)
	if lerr != nil {
		return nil, lerr
	}
	trimmed := strings.TrimSpace(natIP)
	// A translated (external) address is IPv4 for both modes. Classify with the
	// colon-strict SSOT so an IPv4-mapped literal (::ffff:203.0.113.1) is
	// rejected exactly as the Rust dataplane rejects it — To4() would fold it
	// and reverse it to a fabricated subscriber.
	if config.NATAddrFamily(trimmed) != "v4" {
		return nil, lerrf(ErrCodeMalformedInput, "translated address %q must be an IPv4 address", natIP)
	}
	ip := net.ParseIP(trimmed)
	if natPort == 0 {
		return nil, lerrf(ErrCodeMalformedInput, "translated port must be 1-65535")
	}
	nat64Refs := nat64ReferencedPools(cfg)

	if poolName != "" {
		pool, ok := cfg.Security.NAT.SourcePools[poolName]
		if !ok || pool == nil {
			return nil, lerrf(ErrCodeUnknownPool, "no source NAT pool named %q in the applied configuration", poolName)
		}
		p, perr := poolParams(pool, nat64Refs[poolName])
		if perr != nil {
			return nil, perr
		}
		return lookupReverseInPool(p, poolName, ip, natPort, gen)
	}

	var results []*ReverseResult
	var matched []string
	for _, name := range sortedDeterministicPoolNames(cfg) {
		p, perr := poolParams(cfg.Security.NAT.SourcePools[name], nat64Refs[name])
		if perr != nil {
			continue
		}
		r, rerr := lookupReverseInPool(p, name, ip, natPort, gen)
		if rerr != nil {
			// Ambiguity inside one pool cannot be resolved by considering other
			// pools. Never discard it and risk returning a different pool's
			// apparently unique (but still non-exact) answer.
			if rerr.Code == ErrCodeAmbiguousPool {
				return nil, rerr
			}
			continue
		}
		results = append(results, r)
		matched = append(matched, name)
	}
	switch len(results) {
	case 1:
		return results[0], nil
	case 0:
		return nil, lerrf(ErrCodeNotFound, "no deterministic pool maps translated %s:%d to a subscriber", natIP, natPort)
	default:
		return nil, lerrf(ErrCodeAmbiguousPool,
			"translated %s:%d is present in multiple deterministic pools (%s); select one with `pool`", natIP, natPort, strings.Join(matched, ", "))
	}
}

func appliedConfig(view AppliedView) (*config.Config, uint64, *LookupError) {
	if !view.Available || view.Config == nil {
		return nil, 0, lerrf(ErrCodeNoAppliedView,
			"no applied NAT configuration is available (dataplane not running or no configuration applied yet)")
	}
	return view.Config, view.Generation, nil
}

func sortedDeterministicPoolNames(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.Security.NAT.SourcePools))
	for name, pool := range cfg.Security.NAT.SourcePools {
		if pool != nil && pool.Deterministic != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// nat64ReferencedPools records the source pools whose deterministic IPv6
// subscriber mappings are actually activated by the applied NAT64 rules.
// An IPv6 deterministic stanza on an unreferenced source pool remains a
// round-robin pool in the dataplane and must not be exposed as deterministic
// by this forensic readback API.
func nat64ReferencedPools(cfg *config.Config) map[string]bool {
	refs := make(map[string]bool)
	if cfg == nil {
		return refs
	}
	for _, rs := range cfg.Security.NAT.NAT64 {
		// Count a pool as deterministically enforced only when the referencing
		// rule is one the dataplane actually installs. buildNAT64Snapshots
		// (pkg/dataplane/userspace/nat64.go) drops a rule with an empty prefix,
		// and userspace-dp/src/nat64.rs skips any rule whose prefix is not
		// EXACTLY `<ipv6>/96` (the RFC 6052 well-known/network-specific prefix
		// this build supports). A rule with an empty, non-/96, or unparseable
		// prefix installs nothing, so its source pool's IPv6 subscribers are
		// never mapped — exposing them as deterministic would confidently
		// report a translation the dataplane does not perform (#5794 forensic
		// accuracy). A bare reference (pre-fold) over-reported these.
		if rs != nil && rs.SourcePool != "" && nat64PrefixInstallable(rs.Prefix) {
			refs[rs.SourcePool] = true
		}
	}
	return refs
}

// nat64PrefixInstallable mirrors the NAT64 rule-prefix gate in
// userspace-dp/src/nat64.rs: a rule installs only when its prefix splits on
// '/' into EXACTLY two parts, the mask parses as 96, and the address parses as
// an IPv6 (not IPv4-mapped) address. An empty prefix, a missing/extra slash, a
// non-/96 mask, or an unparseable address makes the dataplane skip the whole
// rule, so the referenced pool is not deterministically enforced.
func nat64PrefixInstallable(prefix string) bool {
	parts := strings.Split(prefix, "/")
	if len(parts) != 2 {
		return false
	}
	if n, err := strconv.Atoi(parts[1]); err != nil || n != 96 {
		return false
	}
	// Colon-strict Go/Rust-parity classification (never To4()): Rust
	// Ipv6Addr::from_str accepts an IPv4-mapped literal such as
	// ::ffff:192.0.2.1/96, so the reference gate must too — To4() would
	// wrongly reject it and report the pool unreferenced while the dataplane
	// installs the rule (a false-negative divergence).
	return config.NATAddrFamily(parts[0]) == "v6"
}

// poolParams resolves a source pool's deterministic block-allocation
// parameters. It mirrors deterministicSourceNATFields (mode 1) and
// deterministicNAT64V6Fields (mode 2) in pkg/dataplane/userspace, and the
// Rust allocator's DeterministicV4 / DeterministicV6, so the lookup and the
// enforced dataplane mapping stay identical.
func poolParams(pool *config.NATPool, nat64Referenced bool) (detParams, *LookupError) {
	var p detParams
	if pool == nil || pool.Deterministic == nil {
		return p, lerrf(ErrCodeNotDeterministic, "pool has no deterministic port allocation configured")
	}
	det := pool.Deterministic
	if det.BlockSize <= 0 || det.HostAddress == "" {
		return p, lerrf(ErrCodeNotDeterministic, "deterministic pool missing block-size or subscriber host address")
	}
	ip, hostNet, err := net.ParseCIDR(det.HostAddress)
	if err != nil {
		return p, lerrf(ErrCodeNotDeterministic, "unparseable subscriber CIDR %q", det.HostAddress)
	}
	ones, bits := hostNet.Mask.Size()
	var mode Mode
	switch {
	case bits == 32 && ip.To4() != nil:
		mode = ModeV4
	case bits == 128 && ip.To4() == nil && (ones == 32 || ones == 64):
		mode = ModeV6
	default:
		return p, lerrf(ErrCodeNotDeterministic,
			"unsupported subscriber prefix %q (need an IPv4 CIDR, or an IPv6 /32 or /64)", det.HostAddress)
	}

	poolV4, perr := expandPoolV4(pool, mode)
	if perr != nil {
		return p, perr
	}
	if len(poolV4) == 0 {
		return p, lerrf(ErrCodeNotDeterministic, "deterministic pool has no external IPv4 addresses")
	}
	p.poolV4 = poolV4
	p.blockSize = uint16(det.BlockSize)

	switch mode {
	case ModeV4:
		// Mode 1: IPv4 subscriber. Uses the pool's own port range.
		portLow, portHigh, ok := poolPortRangeV4(pool)
		if !ok {
			return p, lerrf(ErrCodeNotDeterministic, "pool has an invalid or unset port range")
		}
		portRange := int(portHigh) - int(portLow) + 1
		if det.BlockSize > portRange {
			return p, lerrf(ErrCodeNotDeterministic, "block-size %d exceeds the pool port range (%d ports)", det.BlockSize, portRange)
		}
		bpi := portRange / det.BlockSize
		if bpi <= 0 || bpi > 0xFFFF {
			return p, lerrf(ErrCodeNotDeterministic, "degenerate blocks-per-address (%d)", bpi)
		}
		hostBits := uint(bits - ones)
		if hostBits >= 32 {
			return p, lerrf(ErrCodeNotDeterministic, "subscriber prefix /%d is too broad", ones)
		}
		base := hostNet.IP.To4()
		if base == nil {
			return p, lerrf(ErrCodeNotDeterministic, "subscriber base is not IPv4")
		}
		p.mode = ModeV4
		p.blocksPerIP = uint16(bpi)
		p.portLow = portLow
		p.hostBaseV4 = binary.BigEndian.Uint32(base)
		p.hostCount = uint32(1) << hostBits
		return p, nil

	case ModeV6:
		// Mode 2: IPv6 subscriber (NAPT64). Fixed NAT64 port range; the
		// subscriber count is pool-bounded (len(pool) * blocks_per_ip),
		// matching the Rust Nat64Prefix build.
		if !nat64Referenced {
			return p, lerrf(ErrCodeNotDeterministic,
				"pool is not referenced by a NAT64 rule; translations are round-robin, not deterministic")
		}
		const portRange = nat64PortHigh - nat64PortLow + 1
		if det.BlockSize > portRange {
			return p, lerrf(ErrCodeNotDeterministic, "block-size %d exceeds the NAT64 port range (%d ports)", det.BlockSize, portRange)
		}
		bpi := portRange / det.BlockSize
		if bpi <= 0 || bpi > 0xFFFF {
			return p, lerrf(ErrCodeNotDeterministic, "degenerate blocks-per-address (%d)", bpi)
		}
		base16 := hostNet.IP.To16()
		if base16 == nil {
			return p, lerrf(ErrCodeNotDeterministic, "subscriber base is not IPv6")
		}
		p.mode = ModeV6
		p.blocksPerIP = uint16(bpi)
		p.portLow = nat64PortLow
		copy(p.hostBaseV6[:], base16)
		p.wordOffset = 4
		if ones == 64 {
			p.wordOffset = 8
		}
		// #9498: the NAT64 capacity product in 64 bits. The Rust
		// `build_deterministic_v6` computes it with `checked_mul` and, on
		// overflow, DOWNGRADES the rule to round-robin. Go used to wrap to a
		// small, wrong capacity and keep answering as if the pool were
		// deterministic, so the two planes disagreed about what is deterministic.
		hostCount := uint64(len(poolV4)) * uint64(bpi)
		if hostCount > math.MaxUint32 {
			return p, lerrf(ErrCodeNotDeterministic,
				"deterministic NAT64 capacity (%d pool addresses x %d blocks) exceeds the 32-bit subscriber space; the dataplane downgrades this pool to round-robin",
				len(poolV4), bpi)
		}
		p.hostCount = uint32(hostCount)
		return p, nil
	}
	return p, lerrf(ErrCodeNotDeterministic, "unsupported deterministic NAT mode %d", mode)
}

// poolPortRangeV4 DELEGATES to config.SourceNATPoolPortRange: default
// 1024-65535, but a configured-yet-invalid range fails closed. It used to be a
// hand-copied third implementation of that rule, alongside the snapshot
// builder's; #6812 F1 made the config package the SSOT (the aggregate budget
// walk has to agree with the builder about which pools install), so this reads
// it rather than mirroring it — the block-boundary parity these derived
// deterministic params depend on is now true by construction, not by review.
func poolPortRangeV4(pool *config.NATPool) (uint16, uint16, bool) {
	return config.SourceNATPoolPortRange(pool)
}

// expandPoolV4 resolves the pool's ordered external IPv4 addresses using the
// dataplane semantics for the selected deterministic mode. Mode 1 mirrors
// Rust expand_pool_address: a CIDR enumerates every host (subject to the
// safety cap). Mode 2 instead mirrors NAT64 parse_pool_v4: only a bare IPv4
// address or explicit /32 is an allocator member; compiler-expanded "a to b"
// ranges arrive as ordered /32 entries. An IPv4 subnet is rejected because
// the NAT64 dataplane filters it rather than expanding it. IPv6 entries are
// skipped in both modes and pool.Address is prepended exactly as the wire
// builders do.
func expandPoolV4(pool *config.NATPool, mode Mode) ([]net.IP, *LookupError) {
	addrs := make([]string, 0, len(pool.Addresses)+1)
	if pool.Address != "" {
		addrs = append(addrs, pool.Address)
	}
	addrs = append(addrs, pool.Addresses...)

	var out []net.IP
	for _, a := range addrs {
		// Classify the family with the colon-strict Go/Rust-parity SSOT
		// (config.NATAddrFamily on the mask-stripped text) — NEVER net.IP.To4().
		// Go folds an IPv4-mapped literal (::ffff:1.2.3.4) into a 4-byte form
		// whose .To4() is non-nil, but Rust Ipv4Addr::from_str / parse_pool_v4
		// REJECT every colon-bearing form and IpAddr classifies it V6. Keying on
		// the un-parsed text reproduces the dataplane's classification exactly
		// (compiler_nat_helpers.go natAddrFamily), so a mapped member is never
		// folded into the v4 index space the allocator does not have.
		fam := config.NATAddrFamily(config.NATCIDRIPPart(a))
		if fam == "" {
			return nil, lerrf(ErrCodeNotDeterministic, "unparseable pool address %q", a)
		}
		if fam == "v6" {
			// A colon-bearing member (including IPv4-mapped) is not a v4 pool
			// address: NAT64 parse_pool_v4 rejects it and skips the WHOLE rule
			// (#3888 all-or-nothing), and the mode-1 v4 allocator excludes it.
			if mode == ModeV6 {
				return nil, lerrf(ErrCodeNotDeterministic,
					"NAT64 deterministic pool member %q is not an IPv4 host; the dataplane skips the whole rule", a)
			}
			continue // mode-1: excluded from the v4 index space
		}
		// fam == "v4": a dotted-quad host, optionally with a CIDR mask.
		if strings.Contains(a, "/") {
			// #6812 F-C: net.ParseCIDR's mask reader accepts a LEADING-ZERO
			// prefix length — it takes `10.0.0.0/016` as `/16` — where
			// netip.ParsePrefix (the control-plane grammar,
			// sourceNATPoolAddressReason) and parse_canonical_prefix_len (the
			// dataplane's, userspace-dp/src/nat/source.rs) both reject it.
			//
			// Without this check the deterministic surface is the most
			// confident liar in the system: the pool is stamped `invalid_pool`
			// and translates NOTHING, while `show`/gRPC/REST answer a
			// forward-mapping query with a 65,536-address pool computed off a
			// member no other layer accepts. That is the #5794 invariant-8
			// forensic failure — the operator-facing map describing a pool the
			// dataplane does not have — and it is the same divergence class
			// #6812 exists to close, one consumer over.
			//
			// Narrowing only: such a pool TRANSLATES NOTHING either way — the
			// snapshot builder stamps it `invalid_pool` and it installs no
			// allocator — so no config that works today changes behaviour; the
			// lookup now reports an error instead of a fiction.
			//
			// #6812 round 7 — the "already refused at commit" half of that
			// sentence was over-broad and is now dropped. It holds only when a
			// pool-mode rule REFERENCES the pool:
			// validateSourceNATPoolAddressGrammarStrict walks RULE REFERENCES,
			// not the pool table, so an UNREFERENCED pool carrying
			// `10.0.0.0/016` compiles STRICT-CLEAN (measured). Such a pool is
			// still stamped unusable, which is why the conclusion stands — it
			// is unusability, not the commit gate, that carries it. Bound by
			// the reject half of
			// TestDeterministicPoolExpansionMatchesSharedGrammarFixture_6812.
			if _, perr := netip.ParsePrefix(a); perr != nil {
				return nil, lerrf(ErrCodeNotDeterministic,
					"pool address %q is not a canonical CIDR (%v); the dataplane refuses it and the pool translates nothing",
					a, perr)
			}
			_, ipnet, err := net.ParseCIDR(a)
			if err != nil {
				return nil, lerrf(ErrCodeNotDeterministic, "unparseable pool address %q", a)
			}
			ones, bits := ipnet.Mask.Size()
			if mode == ModeV6 && ones != 32 {
				// NAT64 parse_pool_v4 accepts only a bare host or /32; a subnet
				// external pool skips the whole rule rather than expanding.
				return nil, lerrf(ErrCodeNotDeterministic,
					"NAT64 deterministic pool requires host (/32) external addresses; subnet %q is not enforced deterministically", a)
			}
			count := uint64(1) << uint(bits-ones)
			if count > maxPoolPrefixHosts {
				return nil, lerrf(ErrCodeNotDeterministic, "pool prefix %q enumerates more than %d addresses", a, maxPoolPrefixHosts)
			}
			base := binary.BigEndian.Uint32(ipnet.IP.To4())
			for i := uint64(0); i < count; i++ {
				out = append(out, uint32ToIP(base+uint32(i)))
			}
			continue
		}
		out = append(out, net.ParseIP(a).To4())
	}
	return out, nil
}

// formatV6 renders 16 bytes in IPv6 notation without net.IP.String()'s
// IPv4-mapped folding — net.IP(::ffff:1.2.3.4).String() returns the dotted
// quad "1.2.3.4", which would report a NAPT64 IPv6 subscriber as an IPv4
// address. netip.Addr preserves the ::ffff: form (verified), so a mode-2
// result always echoes the subscriber as the IPv6 the operator queried.
func formatV6(b []byte) string {
	var a [16]byte
	copy(a[:], b)
	return netip.AddrFrom16(a).String()
}

func lookupForwardInPool(p detParams, poolName string, host net.IP, fam string, gen uint64) (*ForwardResult, *LookupError) {
	switch p.mode {
	case ModeV4:
		// fam is the colon-strict Go/Rust family of the query text: a mapped
		// literal is "v6" and must NOT map in a mode-1 pool (Rust mode 1 only
		// handles IpAddr::V4).
		if fam != "v4" {
			return nil, lerrf(ErrCodeMalformedInput, "pool %q is IPv4 deterministic; the subscriber must be an IPv4 address", poolName)
		}
		ip4 := host.To4()
		srcH := binary.BigEndian.Uint32(ip4)
		if srcH < p.hostBaseV4 {
			return nil, lerrf(ErrCodeOutOfRange, "subscriber %s is below the pool subscriber range", ip4)
		}
		subIdx := srcH - p.hostBaseV4
		if subIdx >= p.hostCount {
			return nil, lerrf(ErrCodeOutOfRange, "subscriber %s is outside the pool subscriber range", ip4)
		}
		ipIdx := subIdx / uint32(p.blocksPerIP)
		blockIdx := subIdx % uint32(p.blocksPerIP)
		if int(ipIdx) >= len(p.poolV4) {
			return nil, lerrf(ErrCodeOutOfRange, "computed pool address index %d out of range", ipIdx)
		}
		low, high := blockPorts(p, blockIdx)
		return &ForwardResult{
			Pool:              poolName,
			Mode:              ModeV4,
			InternalHost:      ip4.String(),
			ExternalIP:        p.poolV4[ipIdx].String(),
			PortLow:           low,
			PortHigh:          high,
			BlockSize:         p.blockSize,
			BlockIndex:        blockIdx,
			AppliedGeneration: gen,
		}, nil

	case ModeV6:
		// Rust passes an Ipv6Addr straight into deterministic_indices_v6, so an
		// IPv4-mapped literal (fam "v6") is a valid subscriber notation here —
		// a To4()-based reject would diverge (false malformed-input).
		if fam != "v6" || host.To16() == nil {
			return nil, lerrf(ErrCodeMalformedInput, "pool %q is IPv6 NAPT64 deterministic; the subscriber must be an IPv6 address", poolName)
		}
		var octets [16]byte
		copy(octets[:], host.To16())
		off := p.wordOffset
		// #4863: the subscriber word alone does not identify the tenant —
		// the prefix bytes before it must match the configured base exactly.
		for i := 0; i < off; i++ {
			if octets[i] != p.hostBaseV6[i] {
				return nil, lerrf(ErrCodeOutOfRange, "subscriber %s is outside the configured subscriber prefix", host)
			}
		}
		srcWord := binary.BigEndian.Uint32(octets[off : off+4])
		baseWord := binary.BigEndian.Uint32(p.hostBaseV6[off : off+4])
		if srcWord < baseWord {
			return nil, lerrf(ErrCodeOutOfRange, "subscriber %s is below the pool subscriber range", host)
		}
		subIdx := srcWord - baseWord
		if subIdx >= p.hostCount {
			return nil, lerrf(ErrCodeOutOfRange, "subscriber %s is beyond the pool-bounded subscriber capacity", host)
		}
		ipIdx := subIdx / uint32(p.blocksPerIP)
		blockIdx := subIdx % uint32(p.blocksPerIP)
		if int(ipIdx) >= len(p.poolV4) {
			return nil, lerrf(ErrCodeOutOfRange, "computed pool address index %d out of range", ipIdx)
		}
		low, high := blockPorts(p, blockIdx)
		return &ForwardResult{
			Pool:              poolName,
			Mode:              ModeV6,
			InternalHost:      formatV6(host.To16()),
			ExternalIP:        p.poolV4[ipIdx].String(),
			PortLow:           low,
			PortHigh:          high,
			BlockSize:         p.blockSize,
			BlockIndex:        blockIdx,
			AppliedGeneration: gen,
		}, nil

	default:
		return nil, lerrf(ErrCodeNotDeterministic, "pool %q is not deterministic", poolName)
	}
}

func lookupReverseInPool(p detParams, poolName string, natIP net.IP, natPort uint16, gen uint64) (*ReverseResult, *LookupError) {
	if p.mode != ModeV4 && p.mode != ModeV6 {
		return nil, lerrf(ErrCodeNotDeterministic, "pool %q is not deterministic", poolName)
	}
	ip4 := natIP.To4()
	if ip4 == nil {
		return nil, lerrf(ErrCodeMalformedInput, "translated address must be an IPv4 address")
	}
	ipIdx := -1
	for i, a := range p.poolV4 {
		if a.Equal(ip4) {
			if ipIdx >= 0 {
				return nil, lerrf(ErrCodeAmbiguousPool,
					"translated address is ambiguous: appears at multiple pool positions")
			}
			ipIdx = i
		}
	}
	if ipIdx < 0 {
		return nil, lerrf(ErrCodeNotFound, "translated IP %s is not in pool %q", ip4, poolName)
	}
	if natPort < p.portLow {
		return nil, lerrf(ErrCodeNotFound, "translated port %d is below the pool low port %d", natPort, p.portLow)
	}
	offset := uint32(natPort - p.portLow)
	blockIdx := offset / uint32(p.blockSize)
	if blockIdx >= uint32(p.blocksPerIP) {
		return nil, lerrf(ErrCodeNotFound, "translated port %d is outside the deterministic block range", natPort)
	}
	// #9498: widen BEFORE multiplying. `uint32(ipIdx)*uint32(blocksPerIP)` wraps
	// for a pool with more than 66,576 addresses at 64,512 blocks per address,
	// and the wrapped index can land BELOW hostCount -- so the lookup returned
	// the WRONG subscriber instead of failing closed (measured on a
	// commit-accepted /16 + /21 pool: 10.1.4.16:17408 attributed to 100.64.0.0,
	// whose real block is 10.0.0.0:1024). This is the lawful-intercept
	// attribution surface. A product past 2^32 is necessarily >= hostCount
	// (which is at most 2^32 - 1), so the comparison below fails closed exactly
	// where the Rust `reverse_deterministic_v4` `checked_mul`/`checked_add`
	// return None.
	sub64 := uint64(ipIdx)*uint64(p.blocksPerIP) + uint64(blockIdx)
	if sub64 >= uint64(p.hostCount) {
		return nil, lerrf(ErrCodeNotFound, "no subscriber maps to %s:%d", ip4, natPort)
	}
	subIdx := uint32(sub64)
	low, high := blockPorts(p, blockIdx)

	var subscriber string
	// #9070: 0 in IPv4 mode -- an exact host has no prefix to render.
	internalPrefixLen := 0
	switch p.mode {
	case ModeV4:
		if subIdx > math.MaxUint32-p.hostBaseV4 {
			return nil, lerrf(ErrCodeNotFound, "subscriber index overflow")
		}
		subscriber = uint32ToIP(p.hostBaseV4 + subIdx).String()
	case ModeV6:
		off := p.wordOffset
		baseWord := binary.BigEndian.Uint32(p.hostBaseV6[off : off+4])
		if subIdx > math.MaxUint32-baseWord {
			return nil, lerrf(ErrCodeNotFound, "subscriber word overflow")
		}
		octets := p.hostBaseV6
		binary.BigEndian.PutUint32(octets[off:off+4], baseWord+subIdx)
		subscriber = formatV6(octets[:])
		// #9070: the unit is the configured prefix PLUS the reconstructed
		// 32-bit subscriber word -- derived from `off`, never from the pool's
		// configured prefix length.
		internalPrefixLen = (off + 4) * 8
	}

	return &ReverseResult{
		Pool:              poolName,
		Mode:              p.mode,
		ExternalIP:        ip4.String(),
		NATPort:           natPort,
		InternalHost:      subscriber,
		InternalPrefixLen: internalPrefixLen,
		PortLow:           low,
		PortHigh:          high,
		BlockSize:         p.blockSize,
		BlockIndex:        blockIdx,
		AppliedGeneration: gen,
	}, nil
}

// DerivedV4Params exposes the mode-1 (IPv4) deterministic parameters this
// package derives for a pool, in the SAME tuple shape as the dataplane wire
// builder deterministicSourceNATFields (pkg/dataplane/userspace). It exists
// only so a parity test can assert the two Go derivations never drift (the
// single-canonical-implementation guarantee, invariant 8). mode is 0 when
// the pool is not a valid mode-1 deterministic pool.
func DerivedV4Params(pool *config.NATPool) (mode uint8, blockSize, blocksPerIP uint16, hostBase, hostCount uint32) {
	p, err := poolParams(pool, false)
	if err != nil || p.mode != ModeV4 {
		return 0, 0, 0, 0, 0
	}
	return uint8(p.mode), p.blockSize, p.blocksPerIP, p.hostBaseV4, p.hostCount
}

// DerivedV6Params exposes the mode-2 (IPv6 / NAPT64) deterministic
// parameters this package derives for a pool, in the SAME shape as the
// dataplane wire builder deterministicNAT64V6Fields. host_count is NOT
// returned (the wire builder omits it — the Rust side derives it from the
// pool size). ok is false when the pool is not a valid mode-2 pool.
func DerivedV6Params(pool *config.NATPool) (blockSize, blocksPerIP uint16, prefixLen uint8, baseStr string, ok bool) {
	// This helper derives the fields for a pool already selected by a NAT64
	// wire builder; the applied-view reference gate belongs to lookup callers.
	p, err := poolParams(pool, true)
	if err != nil || p.mode != ModeV6 {
		return 0, 0, 0, "", false
	}
	prefixLen = 32
	if p.wordOffset == 8 {
		prefixLen = 64
	}
	return p.blockSize, p.blocksPerIP, prefixLen, net.IP(p.hostBaseV6[:]).String(), true
}

// blockPorts returns the inclusive [low, high] port block for blockIdx.
func blockPorts(p detParams, blockIdx uint32) (uint16, uint16) {
	low := p.portLow + uint16(blockIdx)*p.blockSize
	high := low + p.blockSize - 1
	return low, high
}

func uint32ToIP(v uint32) net.IP {
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// Render writes a Junos-style block for a forward result. Shared by the
// local and remote CLI so both render identically.
func (r *ForwardResult) Render(w io.Writer) {
	fmt.Fprintf(w, "Deterministic NAT mapping (subscriber -> translated)\n")
	fmt.Fprintf(w, "  Pool:              %s\n", r.Pool)
	fmt.Fprintf(w, "  Mode:              %d (%s)\n", r.Mode, r.Mode)
	fmt.Fprintf(w, "  Internal host:     %s\n", r.InternalHost)
	fmt.Fprintf(w, "  Translated IP:     %s\n", r.ExternalIP)
	fmt.Fprintf(w, "  Port block:        %d-%d\n", r.PortLow, r.PortHigh)
	fmt.Fprintf(w, "  Block size:        %d\n", r.BlockSize)
	fmt.Fprintf(w, "  Block index:       %d\n", r.BlockIndex)
	fmt.Fprintf(w, "  Applied generation: %d\n", r.AppliedGeneration)
}

// Render writes a Junos-style block for a reverse result.
func (r *ReverseResult) Render(w io.Writer) {
	fmt.Fprintf(w, "Deterministic NAT mapping (translated -> subscriber)\n")
	fmt.Fprintf(w, "  Pool:              %s\n", r.Pool)
	fmt.Fprintf(w, "  Mode:              %d (%s)\n", r.Mode, r.Mode)
	fmt.Fprintf(w, "  Translated IP:     %s\n", r.ExternalIP)
	fmt.Fprintf(w, "  Translated port:   %d\n", r.NATPort)
	// #9070: a bare address under "Internal host" reads as an exact /128. On
	// the REVERSE lookup the value is the deterministic UNIT's network base, so
	// it is rendered with that unit's length and under a label that says so.
	// ForwardResult.Render is deliberately NOT changed: there InternalHost is
	// the exact host the operator supplied, not a reconstructed base.
	if r.InternalPrefixLen > 0 {
		fmt.Fprintf(w, "  Internal prefix:   %s/%d\n", r.InternalHost, r.InternalPrefixLen)
	} else {
		fmt.Fprintf(w, "  Internal host:     %s\n", r.InternalHost)
	}
	fmt.Fprintf(w, "  Port block:        %d-%d\n", r.PortLow, r.PortHigh)
	fmt.Fprintf(w, "  Block size:        %d\n", r.BlockSize)
	fmt.Fprintf(w, "  Block index:       %d\n", r.BlockIndex)
	fmt.Fprintf(w, "  Applied generation: %d\n", r.AppliedGeneration)
}
