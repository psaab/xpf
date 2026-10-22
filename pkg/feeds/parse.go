package feeds

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// maxLineBytes is the per-line scanner token cap. The default bufio.Scanner cap
// is 64 KB; a single overlong line silently truncates the whole set with the
// default cap, so we raise it. A line longer than this is treated as a failed
// fetch (bufio.ErrTooLong) rather than a silent truncation — see fetchFeed.
const maxLineBytes = 1 << 20 // 1 MiB

// maxInvalidSample bounds how many distinct malformed lines are retained for
// operator display (#2993). A degraded feed records the total invalid-line
// count plus a small sample so an operator can identify the bad lines without
// the sample growing unbounded for a wholesale-garbage body. This is a COUNT
// bound; each retained entry is additionally BYTE-bounded (see
// maxInvalidSampleBytes, #4922).
const maxInvalidSample = 5

// maxInvalidSampleBytes caps the RAW byte prefix of a single malformed line
// retained in the sample (#4922). A malformed line may be up to maxLineBytes
// (1 MiB) long; the pre-#4922 code appended the whole line VERBATIM, so a
// hostile/broken provider serving near-1-MiB malformed lines could pin ~5 MiB
// of garbage in memory (retained in feedState, deep-copied by AllFeeds) and emit
// multi-MB slog records on the degraded-feed warning — all within the advertised
// feed limits. We now keep only the first maxInvalidSampleBytes bytes of each
// offending line, escaped to a printable form, plus its true byte length, so an
// operator can still triage "line was 1 MiB, starts with <prefix>" without
// retaining the whole thing.
const maxInvalidSampleBytes = 256

// maxInvalidSampleEntryBytes is the HARD per-entry ceiling on a retained sample
// string AFTER escaping + length annotation (#4922). strconv.Quote can expand
// each raw byte to a 4-char \xNN escape, so a maxInvalidSampleBytes-byte prefix
// quotes to at most 4*maxInvalidSampleBytes+2 chars; the truncation annotation
// (" … (<n> bytes total)") adds a small bounded suffix. This constant is the
// assertion anchor for the #4922 fail-on-revert test and the defensive final
// clamp in boundInvalidSample.
const maxInvalidSampleEntryBytes = 4*maxInvalidSampleBytes + 64

// maxInvalidSampleTotalBytes is a belt-and-suspenders ceiling on the SUM of the
// retained sample entry lengths across all maxInvalidSample entries (#4922).
// The per-entry cap already bounds each string; this aggregate budget is a live
// second guard so even a future change that loosens the per-entry cap cannot
// grow the retained sample without bound. In the current tuning it equals the
// count cap times the per-entry cap, so the worst legitimate case (5 fully
// escaped 256-byte prefixes) fits exactly and the gate degrades gracefully only
// if the per-entry cap is later raised.
const maxInvalidSampleTotalBytes = maxInvalidSample * maxInvalidSampleEntryBytes

// maxFeedPrefixes aliases the config-time limit so operators cannot configure
// a threshold the parser can never reach.
const maxFeedPrefixes = config.MaxDynamicAddressFeedPrefixes

// fetchResult is the parsed outcome of a single feed read, separated from the
// snapshot-mutation step so the parse path is independently testable.
type fetchResult struct {
	prefixes []string // canonicalized, deduped, sorted
	hash     [32]byte

	// invalidLines counts malformed lines skipped during parse; invalidSample
	// holds up to maxInvalidSample byte-bounded, escaped offenders (#2993,
	// byte-bounded in #4922). A clean body leaves both zero/nil.
	invalidLines  int
	invalidSample []string
}

// countingReader wraps an io.Reader and tracks the total number of bytes read
// through it, so parseFeed can DETECT (not merely truncate at) an over-size
// body: the body is read through io.LimitReader(r, maxFeedBodyBytes+1), and if
// the counter passes maxFeedBodyBytes the feed exceeded the cap (#3934).
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// parseFeed reads CIDR/IP lines from r and returns a canonicalized set.
// It refuses both explicit default-route entries (#9248) and a canonical
// prefix union that covers an entire address family (#10711).
//
// The body is bounded on TWO axes (#3934) so a huge/infinite body or a MITM on
// a plaintext-http feed cannot OOM the daemon:
//   - total bytes: read through io.LimitReader(r, maxFeedBodyBytes+1); a body
//     larger than maxFeedBodyBytes fails the whole fetch (retain last-good),
//   - parsed entries: a body producing more than maxFeedPrefixes parsed entries
//     fails the whole fetch (never install a partial-but-huge set).
//
// Both over-limit conditions return an error so fetchFeed→recordFailure keeps
// the last-good snapshot rather than wiping or truncating the enforced set.
func parseFeed(r io.Reader) (fetchResult, error) {
	var prefixes []string
	var invalidLines int
	var invalidSample []string
	var invalidSampleBytes int   // running total of retained sample-entry lengths (#4922)
	var refusedDefaultRoutes int // #9248: whole-address-space lines refused
	// Cap the total bytes buffered. Read one byte past the cap so a body that
	// exactly fills the cap is accepted while anything larger is detected.
	cr := &countingReader{r: io.LimitReader(r, maxFeedBodyBytes+1)}
	scanner := bufio.NewScanner(cr)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Validate + canonicalize as CIDR or plain IP.
		if _, ipNet, err := net.ParseCIDR(line); err == nil && isDefaultRoute9248(ipNet) {
			// #9248: a feed line naming the whole address space is refused, not
			// installed. Feed prefixes become the address set a policy MATCHES
			// (pkg/dataplane/userspace policies_lower / policies_addrbook), so
			// one `0.0.0.0/0` or `::/0` line in content this box does not author
			// turns every policy on that dynamic address into "match anything":
			// a permit fails open and a deny drops everything. No real feed
			// entry is the default route -- bogon lists stop at /3 and /4 -- so
			// only /0 is refused, and it is counted and sampled exactly like a
			// malformed line so the feed reports DEGRADED instead of a clean
			// success. A feed whose only entry was the default route is left
			// with no usable prefixes and fails with a reason that says so.
			//
			// The test is on the CANONICAL form, the string that would be
			// installed, not on the parsed mask length: `::ffff:0:0/96` is a /96
			// mapped-IPv6 prefix that net.IPNet renders as `0.0.0.0/0`.
			//
			// The assembled prefix set is also checked below: a provider must
			// not evade this refusal by splitting the address space into ranges.
			refusedDefaultRoutes++
			invalidLines++
			if len(invalidSample) < maxInvalidSample && invalidSampleBytes < maxInvalidSampleTotalBytes {
				entry := boundInvalidSample("default route refused: " + line)
				invalidSample = append(invalidSample, entry)
				invalidSampleBytes += len(entry)
			}
		} else if err == nil {
			// Normalize to masked network form (e.g. 192.0.2.5/24 -> 192.0.2.0/24).
			prefixes = append(prefixes, ipNet.String())
		} else if ip := net.ParseIP(line); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				prefixes = append(prefixes, fmt.Sprintf("%s/32", v4.String()))
			} else {
				prefixes = append(prefixes, fmt.Sprintf("%s/128", ip.String()))
			}
		} else {
			// A non-comment line that is neither a CIDR nor a bare IP. Feed
			// providers occasionally emit stray text, but a malformed line can
			// also be THE line that matters for a denylist (#2993). We still
			// skip it (the published valid prefixes are installed), but it is no
			// longer silent: count it and keep a bounded sample so the fetch is
			// observably degraded rather than reporting a clean success.
			//
			// #4922: retain only a BYTE-bounded, escaped prefix of each offender
			// (not the verbatim line, which the scanner admits up to
			// maxLineBytes = 1 MiB). Bounding here, at the retention point, means
			// installSnapshot, AllFeeds' deep copy, and the degraded-feed
			// slog.Warn all inherit the small, safe form — a hostile provider
			// serving near-1-MiB garbage lines can no longer pin megabytes in
			// memory or emit multi-MB log records. Both a COUNT cap
			// (maxInvalidSample) and an aggregate BYTE budget
			// (maxInvalidSampleTotalBytes) gate the append.
			invalidLines++
			if len(invalidSample) < maxInvalidSample && invalidSampleBytes < maxInvalidSampleTotalBytes {
				entry := boundInvalidSample(line)
				invalidSample = append(invalidSample, entry)
				invalidSampleBytes += len(entry)
			}
		}
		// Entry cap: bail as soon as the parsed set exceeds the per-feed limit
		// so the slice memory stays bounded during the loop and a huge feed is
		// rejected rather than truncated-and-installed (#3934).
		if len(prefixes) > maxFeedPrefixes {
			return fetchResult{}, fmt.Errorf("feed exceeds max entry count %d", maxFeedPrefixes)
		}
	}
	if err := scanner.Err(); err != nil {
		// Overlong line (bufio.ErrTooLong) or transport read error mid-stream.
		// Treat the entire read as failed — never install a truncated set.
		return fetchResult{}, fmt.Errorf("read body: %w", err)
	}
	if cr.n > maxFeedBodyBytes {
		// Body exceeded the size cap (the LimitReader delivered the extra
		// sentinel byte). Fail the whole fetch — never install a truncated set,
		// and keep the last-good snapshot (#3934).
		return fetchResult{}, fmt.Errorf("feed body exceeds max size %d bytes", maxFeedBodyBytes)
	}

	canon := canonicalize(prefixes)
	if coversWholeAddressSpace(canon) {
		return fetchResult{}, fmt.Errorf(
			"feed prefix union covers a whole address space (IPv4 or IPv6); refusing the feed (#10711)")
	}
	if len(canon) == 0 && refusedDefaultRoutes > 0 {
		// #9248: say WHY, instead of the generic zero-prefix error below.
		return fetchResult{}, fmt.Errorf("feed contained no usable prefixes: its %d whole-address-space "+
			"entr(y/ies) (0.0.0.0/0, ::/0 or a mapped equivalent) are refused", refusedDefaultRoutes)
	}
	if len(canon) == 0 {
		// Zero-prefix HTTP-200: suspect. Retain last-good rather than installing
		// an empty set that would fail-open an enforced denylist.
		return fetchResult{}, fmt.Errorf("feed returned no usable prefixes")
	}

	return fetchResult{
		prefixes:      canon,
		hash:          hashPrefixes(canon),
		invalidLines:  invalidLines,
		invalidSample: invalidSample,
	}, nil
}

// isDefaultRoute9248 reports whether a parsed prefix is the whole IPv4 or IPv6
// address space (#9248).
func isDefaultRoute9248(n *net.IPNet) bool {
	s := n.String()
	return s == "0.0.0.0/0" || s == "::/0"
}

// boundInvalidSample renders a malformed feed line into the small, safe form
// retained for the degraded-feed sample (#4922). It:
//
//   - truncates the line to at most maxInvalidSampleBytes RAW bytes,
//   - escapes the (possibly truncated) prefix with strconv.Quote so NUL,
//     newline, control bytes, and invalid UTF-8 become printable \x.. / \n
//     escapes — never raw control bytes into a slog record or a CLI show,
//   - annotates a truncated line with its ORIGINAL byte length so an operator
//     can still see "this line was 1 MiB, starts with <prefix>".
//
// A short line (< the byte cap) is returned quoted-but-otherwise-intact, so the
// diagnostic value for the common stray-text case is preserved. A final
// defensive clamp guarantees the result never exceeds maxInvalidSampleEntryBytes
// even if strconv.Quote's expansion is looser than assumed; the clamp keeps the
// string printable (it only trims already-escaped ASCII).
func boundInvalidSample(line string) string {
	orig := len(line)
	prefix := line
	truncated := false
	if orig > maxInvalidSampleBytes {
		prefix = line[:maxInvalidSampleBytes]
		truncated = true
	}
	out := strconv.Quote(prefix)
	if truncated {
		out = fmt.Sprintf("%s … (%d bytes total)", out, orig)
	}
	if len(out) > maxInvalidSampleEntryBytes {
		out = out[:maxInvalidSampleEntryBytes]
	}
	return out
}

// canonicalize dedups and sorts the prefix list. Input prefixes are already in
// masked/normalized string form from parseFeed.
func canonicalize(prefixes []string) []string {
	if len(prefixes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(prefixes))
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// coversWholeAddressSpace reports whether prefixes cover all of either
// address family. It sorts their address ranges and looks for an uninterrupted
// run from the family's unspecified address through its maximum address.
// Input is the canonicalized set from parseFeed.
func coversWholeAddressSpace(prefixes []string) bool {
	ranges := make([]netip.Prefix, 0, len(prefixes))
	for _, text := range prefixes {
		if prefix, err := netip.ParsePrefix(text); err == nil {
			ranges = append(ranges, prefix.Masked())
		}
	}
	sort.Slice(ranges, func(i, j int) bool {
		if cmp := ranges[i].Addr().Compare(ranges[j].Addr()); cmp != 0 {
			return cmp < 0
		}
		return ranges[i].Bits() < ranges[j].Bits()
	})

	for first := 0; first < len(ranges); {
		is4 := ranges[first].Addr().Is4()
		last := first + 1
		for last < len(ranges) && ranges[last].Addr().Is4() == is4 {
			last++
		}

		var coveredThrough netip.Addr
		coveredFromZero := false
		for _, prefix := range ranges[first:last] {
			start := prefix.Addr()
			end := prefixLastAddress(prefix)
			if !coveredFromZero {
				if !start.IsUnspecified() {
					break
				}
				coveredThrough = end
				coveredFromZero = true
			} else {
				next := coveredThrough.Next()
				if !next.IsValid() {
					return true
				}
				if start.Compare(next) > 0 {
					break
				}
				if end.Compare(coveredThrough) > 0 {
					coveredThrough = end
				}
			}
			if !coveredThrough.Next().IsValid() {
				return true
			}
		}
		first = last
	}
	return false
}

// prefixLastAddress returns the inclusive upper bound of a masked prefix.
func prefixLastAddress(prefix netip.Prefix) netip.Addr {
	if prefix.Addr().Is4() {
		bytes := prefix.Addr().As4()
		hostBits := 32 - prefix.Bits()
		for i := len(bytes) - 1; i >= 0 && hostBits > 0; i-- {
			setBits := hostBits
			if setBits > 8 {
				setBits = 8
			}
			bytes[i] |= byte((1 << uint(setBits)) - 1)
			hostBits -= setBits
		}
		return netip.AddrFrom4(bytes)
	}

	bytes := prefix.Addr().As16()
	hostBits := 128 - prefix.Bits()
	for i := len(bytes) - 1; i >= 0 && hostBits > 0; i-- {
		setBits := hostBits
		if setBits > 8 {
			setBits = 8
		}
		bytes[i] |= byte((1 << uint(setBits)) - 1)
		hostBits -= setBits
	}
	return netip.AddrFrom16(bytes)
}

// hashPrefixes returns the sha256 of the canonical (sorted, deduped) set.
// The input must already be sorted+deduped so the hash is content-stable.
func hashPrefixes(canon []string) [32]byte {
	h := sha256.New()
	for _, p := range canon {
		h.Write([]byte(p))
		h.Write([]byte{'\n'})
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
