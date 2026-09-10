package userspace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// Address-book table building and CIDR content canonicalization.
// Split from policies.go (#4421) with no logic change.

// addressBookProbeLimit bounds the deterministic linear probe used to resolve
// a folded-hash collision when assigning a u32 address-book content ID. The
// folded FNV hash gives a starting slot; on a collision we walk forward by one
// slot at a time. The walk is bounded by the number of buckets actually being
// assigned plus a small fixed margin, NOT by a magic constant: with N distinct
// content buckets, at most N-1 prior IDs are taken, so a probe sequence of
// length N is guaranteed to land on a free slot in the 2^32 ID space (which is
// astronomically larger than any realistic N). Exceeding the bound therefore
// signals a builder logic error, not a credible accidental collision — and even
// then we return an error rather than panicking the daemon (#2514).
const addressBookProbeMargin = 8

// addressBookProbeLimit returns the maximum number of linear-probe steps
// allowed when resolving a folded-hash content-ID collision for nBuckets
// distinct content buckets. With at most nBuckets-1 IDs already taken, a
// forward probe of nBuckets steps is guaranteed to reach a free slot in the
// 2^32 space, so in production this bound is never reached — the
// AddressBookIDCollisionError it guards is the fail-safe, not a routine path.
// It is a package var so the #2514 fail-on-revert test can shrink the bound to
// deterministically drive the collision-exhaustion branch (proving it returns
// an error rather than panicking). Production code never reassigns it.
var addressBookProbeLimit = func(nBuckets int) int {
	return nBuckets + addressBookProbeMargin
}

// AddressBookIDCollisionError reports that the deterministic content-ID probe
// could not assign a unique u32 ID to every address-book content bucket. It is
// returned (never panicked) up the snapshot-build / apply path so a commit or
// apply rejects the offending config and the prior dataplane state is retained
// (fail-closed). FNV is not collision-resistant, so this is the defined
// failure mode for the (astronomically unlikely) case of unresolvable folded
// collisions among the configured address-book content buckets.
type AddressBookIDCollisionError struct {
	// BucketCount is the number of distinct content buckets being assigned.
	BucketCount int
	// Probes is the number of probe steps attempted before giving up.
	Probes int
}

func (e *AddressBookIDCollisionError) Error() string {
	return fmt.Sprintf(
		"address-book content-ID collision could not be resolved within %d probes (bucket count = %d); reject config, retain prior dataplane state",
		e.Probes, e.BucketCount)
}

// addressBookContentHash64 derives the FNV-1a/64 hash of an address-book
// content bucket's canonical bytes. It is a package var (not an inline call)
// solely so the #2514 fail-on-revert test can inject a degenerate hash that
// forces every bucket into the same folded-ID probe sequence — exercising the
// collision-exhaustion path that must return an AddressBookIDCollisionError
// instead of panicking. Production code never reassigns it.
var addressBookContentHash64 = func(canon []byte) uint64 {
	h := fnv.New64a()
	h.Write(canon)
	return h.Sum64()
}

// classifyPolicyAddresses splits the policy's address-token list
// into (book IDs, free-form CIDR literals). #1606. The returned
// bookIDs are sorted + deduped.
//
// Precedence, in order: a match-all keyword (`any`, `any4`, `any6`,
// `any-ipv4`, `any-ipv6`) is always a literal; then a known book name; then a
// free-form literal. #9523 moved the keyword test FIRST. Before it, an address,
// address-set or dynamic-address binding literally named `any` resolved to a
// book ID here, so every `match ... any` in every policy matched only that
// object's prefixes. Name-before-literal is kept for every other token (an
// entry named `10.0.1.0/24` with another value is still resolved by name).
func classifyPolicyAddresses(cfg *config.Config, nameToID map[string]uint32, addrs []string) ([]uint32, []string) {
	if len(addrs) == 0 {
		return nil, nil
	}
	bookSet := make(map[uint32]struct{}, len(addrs))
	literals := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, tok := range addrs {
		if tok == "" {
			continue
		}
		if !config.IsPolicyAddressWildcardKeyword(tok) {
			if id, ok := nameToID[tok]; ok {
				bookSet[id] = struct{}{}
				continue
			}
		}
		// A match-all keyword, or not a known book name → a free-form literal:
		// "any", "any4", "any6", "any-ipv4", "any-ipv6", or a CIDR/IP literal.
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		literals = append(literals, tok)
	}
	if len(bookSet) == 0 {
		return nil, literals
	}
	bookIDs := make([]uint32, 0, len(bookSet))
	for id := range bookSet {
		bookIDs = append(bookIDs, id)
	}
	sort.Slice(bookIDs, func(i, j int) bool { return bookIDs[i] < bookIDs[j] })
	return bookIDs, literals
}

// buildAddressBookTable builds the deduplicated #1606 address-book
// table for inclusion on the wire ConfigSnapshot. Returns the
// table + a map from each declared address-book name (Addresses
// and AddressSets) to its assigned u32 ID. Names that reference
// the same canonical CIDR content share an ID.
//
// HA determinism: names are iterated in lexicographic sorted order
// before any hashing/ID assignment. Content hashing buckets by
// canonical bytes (not by hash), and the bucket sort key is
// (hash64, canonical_bytes) so collision-resolution is fully
// deterministic across HA peers.
func buildAddressBookTable(cfg *config.Config) ([]AddressBookSnapshot, map[string]uint32, error) {
	return buildAddressBookTableWithFeeds(cfg, nil)
}

// buildAddressBookTableWithFeeds is buildAddressBookTable plus the
// dynamic-address feed-prefix overlay (#2049). feedOverlay maps an
// address-name (a `security dynamic-address address-name ... profile
// feed-name` binding) to the union of its live feed-backed CIDR strings
// (resolved by the daemon from feeds.Manager.SnapshotForBindings).
//
// For each overlay name the feed CIDRs are merged into that name's content
// bucket BEFORE canonicalize/dedup/sort/hash/ID-assign, so:
//   - the name gets an AddressBookSnapshot row carrying the feed prefixes,
//   - nameToID[name] is populated, so classifyPolicyAddresses routes a policy
//     token naming the feed into SourceBookIDs/DestinationBookIDs (it was a
//     no-match literal before #2049),
//   - a feed-backed name with identical content to a static book shares an ID
//     (the content-equality invariant is preserved — feed CIDRs flow through
//     the same expand/normalize/dedup path),
//   - a feed content change shifts the row → the snapshot content hash shifts
//     → the duplicate-publish gate (snapshotContentHash) lets the refresh
//     through. This is why the join MUST live in the snapshot builder.
//
// An overlay name that IS present but carries no prefixes still produces a
// (possibly empty) bucket and a nameToID entry, so the policy token routes as a
// book reference to an empty set (match-none). NOTE (#5645): the daemon's
// feeds.Manager.SnapshotForBindings no longer EMITS such a present-but-empty
// entry for an UNREADY feed (before its first successful fetch / after a
// hold-interval drop) — it OMITS the name so the token is unresolved and the
// referencing policy fails CLOSED (unrepresentable -> __unsupported_address__
// -> whole-snapshot reject; see buildPolicySnapshots' addrRepresentable and
// #3261). Publishing an empty entry was a DENY fail-open (match-none = the deny
// never fires). This empty-bucket path is therefore now only reachable for a
// non-daemon caller that hands in an explicit empty slice; it is retained as
// defensive, no-panic handling, not a live fail-open.
//
// When the static AddressBook is nil but a feed overlay is present, the table
// is still built from the overlay alone (the pre-#2049 early-return only fired
// because there were no static books to enumerate).
func buildAddressBookTableWithFeeds(cfg *config.Config, feedOverlay map[string][]string) ([]AddressBookSnapshot, map[string]uint32, error) {
	if cfg == nil {
		return nil, nil, nil
	}
	ab := cfg.Security.AddressBook
	if ab == nil && len(feedOverlay) == 0 {
		return nil, nil, nil
	}

	// Collect all unique names: static Addresses + AddressSets ∪ feed-overlay
	// names. A feed-backed name need not exist in the static book at all.
	nameSet := make(map[string]struct{})
	if ab != nil {
		for name := range ab.Addresses {
			nameSet[name] = struct{}{}
		}
		for name := range ab.AddressSets {
			nameSet[name] = struct{}{}
		}
	}
	for name := range feedOverlay {
		nameSet[name] = struct{}{}
	}
	allNames := make([]string, 0, len(nameSet))
	for name := range nameSet {
		allNames = append(allNames, name)
	}
	sort.Strings(allNames)

	type bucket struct {
		canonical []byte
		hash64    uint64
		names     []string // declaring names in this bucket, sorted
		v4        []string
		v6        []string
	}
	contentToBucket := make(map[string]*bucket)
	for _, name := range allNames {
		// #2049 / #3294: expandBookNameToCIDRs is feed-aware — it merges the
		// live feed prefixes bound to this name AND to any feed-bound MEMBER
		// nested inside an address-set (so a `deny <set-containing-a-feed>`
		// enforces the feed portion, closing the #3294 under-deny). The feed
		// CIDRs join the same dedup/sort/canonicalize path as static members,
		// so a feed-backed name with content identical to a static book still
		// shares an ID by the existing content-equality invariant.
		v4, v6 := expandBookNameToCIDRs(cfg, feedOverlay, name)
		// Normalise "any" → 0.0.0.0/0 + ::/0 (Codex r6 refinement).
		v4, v6 = normalizeAnyInCIDRs(v4, v6)
		// Canonical sort + dedup within each family. Without
		// dedup, two books that differ only by repeated members
		// would canonicalize to different bytes and not share an
		// ID (Codex code-review F3).
		sortV4CIDRs(v4)
		sortV6CIDRs(v6)
		v4 = dedupSortedStrings(v4)
		v6 = dedupSortedStrings(v6)
		canon := canonicalizeAddressBookContent(v4, v6)
		key := string(canon)
		b, exists := contentToBucket[key]
		if !exists {
			b = &bucket{canonical: canon, hash64: addressBookContentHash64(canon), v4: v4, v6: v6}
			contentToBucket[key] = b
		}
		b.names = append(b.names, name) // already in sorted-name order
	}

	// Sort buckets by (hash64, canonical_bytes) for deterministic
	// ID assignment.
	buckets := make([]*bucket, 0, len(contentToBucket))
	for _, b := range contentToBucket {
		buckets = append(buckets, b)
	}
	sort.Slice(buckets, func(i, j int) bool {
		if buckets[i].hash64 != buckets[j].hash64 {
			return buckets[i].hash64 < buckets[j].hash64
		}
		return bytes.Compare(buckets[i].canonical, buckets[j].canonical) < 0
	})

	// Assign u32 IDs via deterministic linear probe. ID 0 is
	// reserved.
	used := make(map[uint32]struct{})
	out := make([]AddressBookSnapshot, 0, len(buckets))
	nameToID := make(map[string]uint32)
	for _, b := range buckets {
		id := uint32(b.hash64 & 0xFFFFFFFF)
		if id == 0 {
			id = 1
		}
		if _, dup := used[id]; dup {
			// Linear probe (deterministic given bucket sort). The
			// walk is bounded by the number of buckets being
			// assigned plus a small margin: with N buckets at most
			// N-1 IDs are already taken, so a free slot is reached
			// within N probes in the 2^32 ID space. Exceeding the
			// bound returns an AddressBookIDCollisionError (#2514)
			// — config-shaped input must never panic a security
			// appliance. The caller rejects the config and retains
			// the prior dataplane state (fail-closed).
			folded := uint32(b.hash64 ^ (b.hash64 >> 32))
			probeLimit := addressBookProbeLimit(len(buckets))
			resolved := false
			for probe := 1; probe <= probeLimit; probe++ {
				cand := folded + uint32(probe)
				if cand == 0 {
					cand = 1
				}
				if _, dup := used[cand]; !dup {
					id = cand
					resolved = true
					break
				}
			}
			if !resolved {
				return nil, nil, &AddressBookIDCollisionError{
					BucketCount: len(buckets),
					Probes:      probeLimit,
				}
			}
		}
		used[id] = struct{}{}
		// Diagnostic name: smallest in this bucket.
		diagName := ""
		if len(b.names) > 0 {
			diagName = b.names[0]
		}
		out = append(out, AddressBookSnapshot{
			ID:         id,
			Name:       diagName,
			PrefixesV4: b.v4,
			PrefixesV6: b.v6,
		})
		for _, n := range b.names {
			nameToID[n] = id
		}
	}
	return out, nameToID, nil
}

// expandBookNameToCIDRs resolves a single address-book name
// (Address or AddressSet, recursively) into its v4 + v6 CIDR
// lists. Returns empty slices if name does not exist.
//
// Junos address-book values can be:
//   - CIDR strings (10.0.0.0/24)
//   - bare IPs (10.0.0.1, normalized to /32 or /128)
//   - "any" → both 0.0.0.0/0 and ::/0
//
// All three forms are surfaced here as canonical CIDRs so the wire
// row carries concrete prefixes.
//
// #3294: the walk is feed-aware. A dynamic-address feed binding name (whether
// it IS the top-level name or appears as a MEMBER nested inside an
// address-set) contributes its live overlay prefixes to the row. Feed CIDRs
// are already canonical (masked) strings; the classifier below normalises a
// bare IP and drops an unparseable value, exactly as the old
// splitFeedPrefixesByFamily did. ab may be nil while feedOverlay carries the
// name (a pure feed binding with no static book), so this does NOT early-return
// on nil ab — expandBookNameRecursive handles a nil book.
func expandBookNameToCIDRs(cfg *config.Config, feedOverlay map[string][]string, name string) ([]string, []string) {
	ab := cfg.Security.AddressBook
	visited := make(map[string]bool)
	values := expandBookNameRecursive(ab, feedOverlay, name, visited, 0)
	var v4, v6 []string
	for _, value := range values {
		if value == "" {
			// #3261: an entry with no compiled prefix (a Junos dns-name /
			// wildcard-address / range-address sub-stanza, or a genuinely empty
			// entry) contributes NOTHING. It must NOT widen to 0.0.0.0/0 + ::/0
			// (the pre-#3261 fail-open: an overbroad deny-all / a permit-any).
			// The referencing policy is rejected upstream via nameRepresentable
			// (the address sentinel -> whole-snapshot reject); this keeps the
			// book row itself honest (match-nothing, per the Junos #2229 intent).
			continue
		}
		if value == "any" {
			v4 = append(v4, "0.0.0.0/0")
			v6 = append(v6, "::/0")
			continue
		}
		if isV4CIDR(value) {
			v4 = append(v4, value)
			continue
		}
		if isV6CIDR(value) {
			v6 = append(v6, value)
			continue
		}
		// Bare IP: normalize to /32 (v4) or /128 (v6).
		if ip := net.ParseIP(value); ip != nil {
			if ip.To4() != nil {
				v4 = append(v4, ip.String()+"/32")
			} else {
				v6 = append(v6, ip.String()+"/128")
			}
		}
	}
	return v4, v6
}

// expandBookNameRecursive resolves named book references via
// path-based cycle detection. No depth cap (matches the legacy
// `resolveUserspaceAddressBookEntry` semantics — Copilot review C2).
// `visited` is mutated on entry and unwound on exit so siblings
// can share parents without false cycles.
//
// #3294 (A′): the walk is feed-aware. A dynamic-address feed binding name
// contributes its live overlay prefixes — at the top level AND when it appears
// as a MEMBER nested inside an address-set. Before this, feed prefixes were
// merged only for the top-level overlay name (in buildAddressBookTableWithFeeds),
// so a `deny <set-containing-a-feed>` enforced only the concrete members and
// silently under-denied the feed portion. Resolving the feed here, in the
// recursive walk, closes that under-deny. A name that is BOTH a feed binding
// and a static address accumulates both. ab may be nil (a pure feed binding
// with no static book), in which case only the overlay prefixes contribute.
func expandBookNameRecursive(ab *config.AddressBook, feedOverlay map[string][]string, name string, visited map[string]bool, _depth int) []string {
	if visited[name] {
		return nil
	}
	visited[name] = true
	defer func() { delete(visited, name) }()
	var out []string
	if feeds := feedOverlay[name]; len(feeds) > 0 {
		out = append(out, feeds...)
	}
	if ab == nil {
		return out
	}
	if addr, ok := ab.Addresses[name]; ok {
		out = append(out, addr.Value)
		return out
	}
	if as, ok := ab.AddressSets[name]; ok {
		for _, member := range as.Addresses {
			out = append(out, expandBookNameRecursive(ab, feedOverlay, member, visited, 0)...)
		}
		for _, nested := range as.AddressSets {
			out = append(out, expandBookNameRecursive(ab, feedOverlay, nested, visited, 0)...)
		}
		return out
	}
	return out
}

func normalizeAnyInCIDRs(v4, v6 []string) ([]string, []string) {
	hasAny4 := false
	hasAny6 := false
	cleanV4 := v4[:0]
	for _, s := range v4 {
		if s == "0.0.0.0/0" {
			hasAny4 = true
		}
		cleanV4 = append(cleanV4, s)
	}
	cleanV6 := v6[:0]
	for _, s := range v6 {
		if s == "::/0" {
			hasAny6 = true
		}
		cleanV6 = append(cleanV6, s)
	}
	_ = hasAny4
	_ = hasAny6
	return cleanV4, cleanV6
}

func sortV4CIDRs(s []string) {
	sort.Slice(s, func(i, j int) bool {
		_, a, errA := net.ParseCIDR(s[i])
		_, b, errB := net.ParseCIDR(s[j])
		if errA != nil || errB != nil {
			return s[i] < s[j]
		}
		if c := bytes.Compare(a.IP, b.IP); c != 0 {
			return c < 0
		}
		ma, _ := a.Mask.Size()
		mb, _ := b.Mask.Size()
		return ma < mb
	})
}

func sortV6CIDRs(s []string) {
	sortV4CIDRs(s) // same logic; works on any net.IP
}

// canonicalizeAddressBookContent serializes the v4 + v6 CIDR
// lists into a fixed byte stream with explicit family + count
// framing (Codex r3 F4 fix).
//
// Layout:
//
//	"V4" || u32_be(len(v4)) || (for each: u8(prefix_len) || u32_be(addr_bytes))
//	"V6" || u32_be(len(v6)) || (for each: u8(prefix_len) || u128_be(addr_bytes))
//
// CIDR strings that fail to parse are skipped (defensive).
func canonicalizeAddressBookContent(v4, v6 []string) []byte {
	var buf bytes.Buffer
	buf.WriteString("V4")
	binary.Write(&buf, binary.BigEndian, uint32(len(v4)))
	for _, s := range v4 {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		buf.WriteByte(byte(ones))
		buf.Write(ipnet.IP.To4())
	}
	buf.WriteString("V6")
	binary.Write(&buf, binary.BigEndian, uint32(len(v6)))
	for _, s := range v6 {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		buf.WriteByte(byte(ones))
		buf.Write(ipnet.IP.To16())
	}
	return buf.Bytes()
}

func dedupSortedStrings(s []string) []string {
	if len(s) <= 1 {
		return s
	}
	out := s[:1]
	for i := 1; i < len(s); i++ {
		if s[i] != out[len(out)-1] {
			out = append(out, s[i])
		}
	}
	return out
}
