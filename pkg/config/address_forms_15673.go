package config

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

// #15673 — native address-book value forms.
//
// Junos `address <name>` takes exactly one value form:
//   - a prefix (IP/CIDR) — stored in Address.Value (pre-existing);
//   - `range-address <low> { to { <high>; } }` (hierarchical) or
//     `range-address <low> to <high>` (flat) — expanded natively at compile
//     time via expandAddressRangeToCIDRCover (minimal CIDR cover, #16563)
//     into Address.ExpandedPrefixes;
//   - `wildcard-address <ip>/<wildcard-mask>` — Junos polarity (#16544):
//     the bits set in the wildcard mask are compared (care bits); a 0 bit
//     is ignored ("don't care"). The entry enforces the single prefix
//     formed by masking with the mask itself, with prefix length
//     popcount(mask), stored in ExpandedPrefixes. Non-contiguous masks
//     have no single CIDR equivalent and stay unimplemented.
//   - `dns-name <fqdn> [ipv4-only|ipv6-only]` — modelled in Address.DNSName /
//     DNSFamily; the current resolution lives in Address.DNSAddresses and is
//     refreshed by the daemon (RefreshDNSAddressBooks). A cold-cache compile
//     marks DNSUnresolved without claiming a lookup failure (#17782). A
//     lookup FAILURE keeps the last good answer (stale-while-error, #16595,
//     flagged by DNSLookupFailed); a successful lookup with no usable address
//     is match-none (fail-closed). Neither is an error.
//
// Unknown/future forms and any entry mixing a prefix with another form stay
// in UnimplementedForms (#9524) and are unusable.

// dnsResolveWorkers bounds concurrent dns-name lookups (#16601).
const dnsResolveWorkers = 8

// dnsResolveAggregateTimeout bounds one whole refresh batch (#16601).
const dnsResolveAggregateTimeout = 10 * time.Second

const dnsPerNameTimeout = 5 * time.Second

// dnsAnswerCache is the daemon-owned answer cache compile reads
// (#16601). Compile performs NO network I/O: applyDNSName populates
// DNSAddresses only from this cache (miss => fail-closed empty marked
// DNSUnresolved). Resolution happens only in
// RefreshDNSAddressBooks, which callers must invoke OUTSIDE
// configstore s.mu and daemon applySem.
var dnsAnswerCache = struct {
	sync.RWMutex
	m map[string][]string
	// ok marks keys resolved successfully (even to empty); a success
	// that found no family-matching IPs must NOT be re-looked-up by
	// Peek. A failed/timed-out lookup leaves ok false so Peek retries.
	ok map[string]bool
}{m: make(map[string][]string), ok: make(map[string]bool)}

func dnsCacheKey(fqdn, family string) string { return fqdn + "\x00" + family }

func dnsCacheGet(fqdn, family string) ([]string, bool) {
	dnsAnswerCache.RLock()
	defer dnsAnswerCache.RUnlock()
	v, ok := dnsAnswerCache.m[dnsCacheKey(fqdn, family)]
	if !ok {
		return nil, false
	}
	return append([]string(nil), v...), true
}

func dnsCachePut(fqdn, family string, prefixes []string) {
	dnsCachePutOK(fqdn, family, prefixes, true)
}

// dnsCachePutOK stores prefixes; success=false records the values
// (fail-closed for compile) without marking the key resolved, so a
// Peek in the daemon re-resolves instead of trusting a failure.
func dnsCachePutOK(fqdn, family string, prefixes []string, success bool) {
	dnsAnswerCache.Lock()
	defer dnsAnswerCache.Unlock()
	k := dnsCacheKey(fqdn, family)
	dnsAnswerCache.m[k] = append([]string(nil), prefixes...)
	if success {
		dnsAnswerCache.ok[k] = true
	} else {
		delete(dnsAnswerCache.ok, k)
	}
}

// dnsCacheFailed reports whether the cached entry's last resolution
// failed (#16595 stale-while-error flag for compile-time populate).
func dnsCacheFailed(fqdn, family string) bool {
	dnsAnswerCache.RLock()
	defer dnsAnswerCache.RUnlock()
	k := dnsCacheKey(fqdn, family)
	_, present := dnsAnswerCache.m[k]
	return present && !dnsAnswerCache.ok[k]
}

// dnsCachePutFailed stores a failed resolution retaining prefixes
// (last-good, #16595) and marks the key not-ok so Peek retries it.
func dnsCachePutFailed(fqdn, family string, prefixes []string) {
	dnsAnswerCache.Lock()
	defer dnsAnswerCache.Unlock()
	k := dnsCacheKey(fqdn, family)
	dnsAnswerCache.m[k] = append([]string(nil), prefixes...)
	delete(dnsAnswerCache.ok, k)
}

// dnsCacheMarkFailed flags an existing cached answer as stale-failed
// without discarding its prefixes (#16595).
func dnsCacheMarkFailed(fqdn, family string) {
	dnsAnswerCache.Lock()
	defer dnsAnswerCache.Unlock()
	delete(dnsAnswerCache.ok, dnsCacheKey(fqdn, family))
}

// SeedDNSAnswerCacheForTest pre-populates the answer cache so tests in
// other packages can drive compile/apply without network (#16601).
func SeedDNSAnswerCacheForTest(fqdn, family string, prefixes []string) func() {
	key := dnsCacheKey(fqdn, family)
	dnsAnswerCache.Lock()
	old, existed := dnsAnswerCache.m[key]
	oldOk := dnsAnswerCache.ok[key]
	dnsAnswerCache.m[key] = append([]string(nil), prefixes...)
	dnsAnswerCache.ok[key] = true
	dnsAnswerCache.Unlock()
	return func() {
		dnsAnswerCache.Lock()
		if existed {
			dnsAnswerCache.m[key] = old
		} else {
			delete(dnsAnswerCache.m, key)
		}
		if oldOk {
			dnsAnswerCache.ok[key] = true
		} else {
			delete(dnsAnswerCache.ok, key)
		}
		dnsAnswerCache.Unlock()
	}
}

// PeekDNSNames lists distinct (fqdn,family) pairs in cfg not yet
// successfully resolved in the answer cache (#16601). Daemon callers
// use it to compile a text config WITHOUT network (e.g. a discarding
// SyncApply) and resolve only when there is something to resolve.
func PeekDNSNames(cfg *Config) [][2]string {
	if cfg == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out [][2]string
	add := func(b *AddressBook) {
		if b == nil {
			return
		}
		for _, a := range b.Addresses {
			if a == nil || a.DNSName == "" {
				continue
			}
			k := dnsCacheKey(a.DNSName, a.DNSFamily)
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			dnsAnswerCache.RLock()
			_, resolved := dnsAnswerCache.ok[k]
			dnsAnswerCache.RUnlock()
			if !resolved {
				out = append(out, [2]string{a.DNSName, a.DNSFamily})
			}
		}
	}
	add(cfg.Security.AddressBook)
	for _, nb := range cfg.Security.NamedAddressBooks {
		if nb != nil {
			add(&nb.AddressBook)
		}
	}
	for _, z := range cfg.Security.Zones {
		if z != nil {
			add(z.AddressBook)
		}
	}
	return out
}

// ResolveDNSNames resolves the given (fqdn,family) pairs into the
// answer cache with the bounded pool (network, outside all locks).
func ResolveDNSNames(pairs [][2]string) {
	if len(pairs) == 0 {
		return
	}
	entries := make([]dnsEntryRef, 0, len(pairs))
	holders := make([]*Address, 0, len(pairs))
	for _, p := range pairs {
		a := &Address{DNSName: p[0], DNSFamily: p[1]}
		holders = append(holders, a)
		entries = append(entries, dnsEntryRef{a, p[0], p[1]})
	}
	_ = holders
	resolveDNSEntriesParallel(entries)
}

// lookupAddressDNSName resolves fqdn to IP strings. Package var so tests
// can substitute a deterministic resolver. Only
// RefreshDNSAddressBooks (outside all locks) may call it via
// resolveDNSEntriesParallel; compile never reaches it (#16601).
var lookupAddressDNSName = func(fqdn string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsPerNameTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a.IP != nil {
			out = append(out, a.IP.String())
		}
	}
	return out, nil
}

// SetLookupAddressDNSNameForTest substitutes the dns-name resolver and
// returns a restore func. It exists for tests in OTHER packages (the
// daemon's periodic-refresh regression, #15933) that drive the resolver
// through RefreshDNSAddressBooks without network access.
func SetLookupAddressDNSNameForTest(fn func(fqdn string) ([]string, error)) func() {
	orig := lookupAddressDNSName
	lookupAddressDNSName = fn
	return func() { lookupAddressDNSName = orig }
}

// dnsIPsToPrefixes converts resolved IPs to /32 or /128 CIDRs, applying the
// family filter, deduplicated and sorted for determinism.
func dnsIPsToPrefixes(ips []string, family string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		is4 := ip.To4() != nil
		if family == "ipv4-only" && !is4 {
			continue
		}
		if family == "ipv6-only" && is4 {
			continue
		}
		var p string
		if is4 {
			p = ip.To4().String() + "/32"
		} else {
			p = ip.String() + "/128"
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// hasSuccessfulFamilyEmptyDNS reports an untainted, family-scoped DNS entry
// whose successful resolution currently has no usable prefixes.
func (a *Address) hasSuccessfulFamilyEmptyDNS() bool {
	return a != nil && a.DNSName != "" &&
		(a.DNSFamily == "ipv4-only" || a.DNSFamily == "ipv6-only") &&
		!a.DNSLookupFailed && !a.DNSUnresolved && a.Value == "" &&
		len(a.DNSAddresses) == 0 && len(a.ExpandedPrefixes) == 0 &&
		len(a.UnimplementedForms) == 0 && len(a.DuplicatePrefixes) == 0 &&
		len(a.TrailingTokens) == 0 && a.OversizedRange == ""
}

// resolveDNSAddressEntry populates one entry FROM THE CACHE ONLY
// (#16601): no network I/O, safe under any lock. Cache hit (key present,
// even with a failed-flag) stamps the cached prefixes and the cached
// DNSLookupFailed state (#16595 stale-while-error is preserved because
// the cache retains the last good answer on failure) and clears
// DNSUnresolved. Cache miss leaves no usable prefixes and marks only
// DNSUnresolved (#17782): "not yet resolved" must not read as a successful
// resolution to zero addresses. RefreshDNSAddressBooks clears the unresolved
// marker after the live attempt, preserving resolver failure separately.
func resolveDNSAddressEntry(a *Address) {
	if a == nil || a.DNSName == "" {
		return
	}
	if prefixes, ok := dnsCacheGet(a.DNSName, a.DNSFamily); ok {
		a.DNSAddresses = prefixes
		a.DNSLookupFailed = dnsCacheFailed(a.DNSName, a.DNSFamily)
		a.DNSUnresolved = false
		return
	}
	a.DNSAddresses = nil
	a.DNSLookupFailed = false
	a.DNSUnresolved = true
}

type dnsEntryRef struct {
	addr   *Address
	fqdn   string
	family string
}

// resolveDNSEntriesParallel resolves distinct (fqdn,family) pairs with
// a bounded worker pool and aggregate deadline, writes results into
// the cache, then populates entries from the cache (#16601/#16595).
// On lookup error the cache KEEPS the last good prefixes and marks the
// key failed (stale-while-error); entries sharing a name resolve once.
func resolveDNSEntriesParallel(entries []dnsEntryRef) {
	if len(entries) == 0 {
		return
	}
	// Capture prior cache state per entry for stale retention: on
	// failure an entry with no cache history keeps its own current
	// DNSAddresses (the clone's seed, #16595).
	prior := make(map[*Address][]string, len(entries))
	for _, e := range entries {
		prior[e.addr] = append([]string(nil), e.addr.DNSAddresses...)
	}
	type job struct{ fqdn, family string }
	seen := make(map[string]struct{})
	var jobs []job
	for _, e := range entries {
		k := dnsCacheKey(e.fqdn, e.family)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		jobs = append(jobs, job{e.fqdn, e.family})
	}
	results := make(map[string][]string, len(jobs))
	succeeded := make(map[string]bool, len(jobs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, dnsResolveWorkers)
	deadline := time.Now().Add(dnsResolveAggregateTimeout)
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			if time.Now().After(deadline) {
				return
			}
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			default:
				sem <- struct{}{}
				defer func() { <-sem }()
			}
			if time.Now().After(deadline) {
				return
			}
			ips, err := lookupAddressDNSName(j.fqdn)
			var prefixes []string
			ok := err == nil
			if ok {
				prefixes = dnsIPsToPrefixes(ips, j.family)
			}
			mu.Lock()
			results[dnsCacheKey(j.fqdn, j.family)] = prefixes
			succeeded[dnsCacheKey(j.fqdn, j.family)] = ok
			mu.Unlock()
		}(j)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(dnsResolveAggregateTimeout):
	}
	for _, j := range jobs {
		k := dnsCacheKey(j.fqdn, j.family)
		mu.Lock()
		prefixes := results[k]
		ok := succeeded[k]
		mu.Unlock()
		if ok {
			dnsCachePutOK(j.fqdn, j.family, prefixes, true)
		} else {
			// Stale-while-error (#16595): keep last good cache answer
			// if any; otherwise leave the key present-failed with the
			// first entry's prior value handled per-entry below.
			if _, has := dnsCacheGet(j.fqdn, j.family); !has {
				dnsCachePutFailed(j.fqdn, j.family, nil)
			} else {
				dnsCacheMarkFailed(j.fqdn, j.family)
			}
		}
	}
	for _, e := range entries {
		k := dnsCacheKey(e.fqdn, e.family)
		mu.Lock()
		ok := succeeded[k]
		mu.Unlock()
		if ok {
			if prefixes, has := dnsCacheGet(e.fqdn, e.family); has {
				e.addr.DNSAddresses = prefixes
			} else {
				e.addr.DNSAddresses = nil
			}
			e.addr.DNSLookupFailed = false
			e.addr.DNSUnresolved = false
		} else {
			e.addr.DNSLookupFailed = true
			e.addr.DNSUnresolved = false
			if prefixes, has := dnsCacheGet(e.fqdn, e.family); has && len(prefixes) > 0 {
				e.addr.DNSAddresses = prefixes
			} else if len(prior[e.addr]) > 0 {
				e.addr.DNSAddresses = prior[e.addr]
				// Seed the cache with this stale answer so compile
				// (cache-only) sees the same retained value.
				dnsCachePutFailed(e.fqdn, e.family, prior[e.addr])
			} else {
				e.addr.DNSAddresses = nil
			}
		}
	}
}

// DNSEntryLookupFailed reports whether a (possibly nested) address-book
// name's closure contains a dns-name entry whose latest resolution FAILED
// (#16595). It excludes names not yet looked up because the compile cache
// was cold.
func (ab *AddressBook) DNSEntryLookupFailed(name string) bool {
	return ab.dnsEntryResolutionState(name, false)
}

// DNSEntryResolutionUnavailable reports whether a (possibly nested)
// address-book name's closure contains a dns-name entry whose answer is
// unavailable because lookup failed or has not run yet (#17782).
func (ab *AddressBook) DNSEntryResolutionUnavailable(name string) bool {
	return ab.dnsEntryResolutionState(name, true)
}

func (ab *AddressBook) dnsEntryResolutionState(name string, includeUnresolved bool) bool {
	if ab == nil {
		return false
	}
	seen := map[string]bool{}
	var walk func(ref string) bool
	walk = func(ref string) bool {
		if seen[ref] {
			return false
		}
		seen[ref] = true
		if a, ok := ab.Addresses[ref]; ok && a != nil {
			return a.DNSName != "" && (a.DNSLookupFailed || (includeUnresolved && a.DNSUnresolved))
		}
		if set, ok := ab.AddressSets[ref]; ok && set != nil {
			for _, m := range set.Addresses {
				if walk(m) {
					return true
				}
			}
			for _, m := range set.AddressSets {
				if walk(m) {
					return true
				}
			}
		}
		return false
	}
	return walk(name)
}

// RefreshDNSAddressBooks re-resolves every dns-name entry with a
// bounded worker pool and aggregate deadline (#16601). NETWORK I/O:
// call only outside configstore s.mu and daemon applySem. MUTATES cfg
// in place; cfg MUST NOT be a published active config (#15933).
func RefreshDNSAddressBooks(cfg *Config) {
	if cfg == nil {
		return
	}
	var entries []dnsEntryRef
	collect := func(b *AddressBook) {
		if b == nil {
			return
		}
		for _, a := range b.Addresses {
			if a != nil && a.DNSName != "" {
				entries = append(entries, dnsEntryRef{a, a.DNSName, a.DNSFamily})
			}
		}
	}
	collect(cfg.Security.AddressBook)
	for _, nb := range cfg.Security.NamedAddressBooks {
		if nb != nil {
			collect(&nb.AddressBook)
		}
	}
	for _, z := range cfg.Security.Zones {
		if z != nil {
			collect(z.AddressBook)
		}
	}
	resolveDNSEntriesParallel(entries)
}

// ResolveDNSForConfig names the lock contract for daemon callers
// (#16601): resolve before acquiring applySem.
func ResolveDNSForConfig(cfg *Config) { RefreshDNSAddressBooks(cfg) }

// HasDNSNames reports whether cfg carries any dns-name entry.
func HasDNSNames(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	has := false
	scan := func(b *AddressBook) {
		if b == nil || has {
			return
		}
		for _, a := range b.Addresses {
			if a != nil && a.DNSName != "" {
				has = true
				return
			}
		}
	}
	scan(cfg.Security.AddressBook)
	for _, nb := range cfg.Security.NamedAddressBooks {
		if nb != nil {
			scan(&nb.AddressBook)
		}
	}
	for _, z := range cfg.Security.Zones {
		if z != nil {
			scan(z.AddressBook)
		}
	}
	return has
}

// PopulateDNSFromCache fills DNSAddresses/DNSLookupFailed/DNSUnresolved
// from the answer cache only (no network) (#16601/#17782).
func PopulateDNSFromCache(cfg *Config) {
	if cfg == nil {
		return
	}
	pop := func(b *AddressBook) {
		if b == nil {
			return
		}
		for _, a := range b.Addresses {
			resolveDNSAddressEntry(a)
		}
	}
	pop(cfg.Security.AddressBook)
	for _, nb := range cfg.Security.NamedAddressBooks {
		if nb != nil {
			pop(&nb.AddressBook)
		}
	}
	for _, z := range cfg.Security.Zones {
		if z != nil {
			pop(z.AddressBook)
		}
	}
}

// RefreshDNSForPreflight returns a private copy of cfg with every
// dns-name entry re-resolved against current DNS (#16612). It never
// mutates cfg: the copy is made via CloneForDNSRefresh, so callers may
// evaluate a frozen compiled config (e.g. a commit-confirmed rollback
// target compiled once at Store.Load) without disturbing the published
// object the store still holds.
func RefreshDNSForPreflight(cfg *Config) *Config {
	if cfg == nil {
		return nil
	}
	clone := cfg.CloneForDNSRefresh()
	if clone == nil {
		return nil
	}
	RefreshDNSAddressBooks(clone)
	return clone
}

// CloneForDNSRefresh returns a private deep copy of cfg for DNS resolution
// and apply. Every exported pointer, map, and slice in the config graph is
// cloned, not just the DNS-resolution state. In particular, a later
// apply-path mutation to a non-DNS object cannot write through to the
// published generation (#17734). Compiler-private metadata is copied with
// its containing value; it is immutable after compilation.
//
// The copy preserves pointer sharing inside the config graph. Its cost is
// O(config size), which is required for the returned config to be safe for
// independent apply-time mutation.
func (cfg *Config) CloneForDNSRefresh() *Config {
	if cfg == nil {
		return nil
	}
	cloned := cloneConfigValue(reflect.ValueOf(cfg), make(map[configCloneVisit]reflect.Value))
	return cloned.Interface().(*Config)
}

// DNSAnswerState is one dns-name entry's runtime DNS state: its current
// prefixes (in order) and whether the latest resolution attempt failed
// (DNSLookupFailed). Both consumers that compare runtime DNS state MUST
// see the failure flag: a successful empty answer and a failed lookup
// retaining an empty (or stale) answer have different enforcement
// semantics (#16595, #17723).
type DNSAnswerState struct {
	Prefixes        []string
	DNSLookupFailed bool
}

// DNSAnswersSnapshot returns identity->DNS state for every dns-name entry,
// using the same scoped identities as the daemon refresher (#16606): the
// global book, each named book, and each zone-local book (including the
// folded zone-local/<zone>/<name> copies in the global book, which carry
// the same scoped identity as their zone-local source). It is the shared
// enumeration every consumer that needs to see runtime DNS state must
// use — the refresher baseline and the userspace hybrid guard — so the
// two cannot drift on scope or ordering. Prefix slices are copied.
// Ordering within an entry is preserved (resolver order); callers that
// compare snapshots must treat order as significant, matching the
// refresher's change detection. The DNSLookupFailed flag is part of the
// compared state (#17723): dropping it would make a failure-only
// transition (successful empty -> SERVFAIL, or SERVFAIL -> successful
// empty, with unchanged prefixes) compare equal and never publish.
func DNSAnswersSnapshot(cfg *Config) map[string]DNSAnswerState {
	out := map[string]DNSAnswerState{}
	if cfg == nil {
		return out
	}
	scan := func(scope string, b *AddressBook) {
		if b == nil {
			return
		}
		for name, a := range b.Addresses {
			if a != nil && a.DNSName != "" {
				out[dnsIdentityKey(scope, name)] = DNSAnswerState{
					Prefixes:        append([]string(nil), a.DNSAddresses...),
					DNSLookupFailed: a.DNSLookupFailed,
				}
			}
		}
	}
	scan("global/", cfg.Security.AddressBook)
	for bookName, nb := range cfg.Security.NamedAddressBooks {
		if nb != nil {
			scan("address-book/"+bookName+"/", &nb.AddressBook)
		}
	}
	for zoneName, z := range cfg.Security.Zones {
		if z != nil {
			scan(ZoneLocalQualify(zoneName, ""), z.AddressBook)
		}
	}
	return out
}

// DNSAnswersDigest returns a content digest of cfg's runtime DNS state:
// every dns-name entry's scoped identity, its current prefixes (in order),
// and its failed/unresolved flags (#16687/#17782). Derived caches that build
// from a config's DNS answers (policymatch's query snapshot) key on this
// digest in addition to the config pointer, so an in-place answer change on
// the same published pointer cannot leave a stale verdict resident. A config
// with no dns-name entries digests to the empty-config digest.
func DNSAnswersDigest(cfg *Config) [sha256.Size]byte {
	h := sha256.New()
	var length [8]byte
	writeCount := func(count int) {
		binary.BigEndian.PutUint64(length[:], uint64(count))
		_, _ = h.Write(length[:])
	}
	write := func(value string) {
		writeCount(len(value))
		_, _ = h.Write([]byte(value))
	}
	if cfg == nil {
		var digest [sha256.Size]byte
		copy(digest[:], h.Sum(nil))
		return digest
	}
	type dnsEntry struct {
		key        string
		prefixes   []string
		failed     bool
		unresolved bool
	}
	var entries []dnsEntry
	scan := func(scope string, b *AddressBook) {
		if b == nil {
			return
		}
		for name, a := range b.Addresses {
			if a != nil && a.DNSName != "" {
				entries = append(entries, dnsEntry{
					key:        dnsIdentityKey(scope, name),
					prefixes:   append([]string(nil), a.DNSAddresses...),
					failed:     a.DNSLookupFailed,
					unresolved: a.DNSUnresolved,
				})
			}
		}
	}
	scan("global/", cfg.Security.AddressBook)
	for bookName, nb := range cfg.Security.NamedAddressBooks {
		if nb != nil {
			scan("address-book/"+bookName+"/", &nb.AddressBook)
		}
	}
	for zoneName, z := range cfg.Security.Zones {
		if z != nil {
			scan(ZoneLocalQualify(zoneName, ""), z.AddressBook)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	writeCount(len(entries))
	for _, e := range entries {
		write(e.key)
		writeCount(len(e.prefixes))
		for _, p := range e.prefixes {
			write(p)
		}
		if e.failed {
			_, _ = h.Write([]byte{1})
		} else {
			_, _ = h.Write([]byte{0})
		}
		if e.unresolved {
			_, _ = h.Write([]byte{1})
		} else {
			_, _ = h.Write([]byte{0})
		}
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// dnsIdentityKey builds a collision-free snapshot key for one dns-name
// entry. The scope is length-prefixed so no operator-authored name (which
// may legally contain '/', e.g. "address-book/eng-book/svc") can alias
// another scope — change detection must merge views on identity, not on
// name shadowing (#15933 C4, #15962 fold).
func dnsIdentityKey(scope, name string) string {
	return fmt.Sprintf("%d:%s%s", len(scope), scope, name)
}

// expandWildcardAddress converts `ip/wildcard-mask` (Junos polarity:
// set mask bits are compared, 0 bits are ignored; e.g.
// 10.1.2.3/255.255.255.0 enforces 10.1.2.0/24) to the single enforced
// prefix. Non-contiguous masks have no CIDR equivalent and are rejected
// so the caller records the form as unimplemented.
func expandWildcardAddress(spec string) (string, error) {
	ipStr, maskStr, ok := strings.Cut(spec, "/")
	if !ok {
		return "", fmt.Errorf("wildcard-address %q: missing wildcard mask", spec)
	}
	if strings.Contains(maskStr, "/") {
		return "", fmt.Errorf("wildcard-address %q: invalid address or mask", spec)
	}
	ip := net.ParseIP(ipStr)
	maskIP := net.ParseIP(maskStr)
	if ip == nil || maskIP == nil {
		return "", fmt.Errorf("wildcard-address %q: invalid address or mask", spec)
	}
	ip4, mask4 := ip.To4(), maskIP.To4()
	var ipB, maskB []byte
	switch {
	case ip4 != nil && mask4 != nil:
		ipB, maskB = ip4, mask4
	case ip4 != nil || mask4 != nil:
		return "", fmt.Errorf("wildcard-address %q: family mismatch", spec)
	default:
		ipB, maskB = ip.To16(), maskIP.To16()
		if ipB == nil || maskB == nil {
			return "", fmt.Errorf("wildcard-address %q: family mismatch", spec)
		}
	}
	network := make([]byte, len(ipB))
	for i := range maskB {
		network[i] = ipB[i] & maskB[i]
	}
	ones, maskBits := net.IPMask(maskB).Size()
	if maskBits == 0 {
		return "", fmt.Errorf("wildcard-address %q: non-contiguous wildcard mask has no CIDR equivalent", spec)
	}
	cidr := fmt.Sprintf("%s/%d", net.IP(network).String(), ones)
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return "", fmt.Errorf("wildcard-address %q: %w", spec, err)
	}
	return cidr, nil
}

func popcountByte(b byte) int {
	n := 0
	for b != 0 {
		n += int(b & 1)
		b >>= 1
	}
	return n
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func isAllOnes(b []byte) bool {
	for _, v := range b {
		if v != 0xff {
			return false
		}
	}
	return true
}

// applyRangeAddress records a range-address expansion on addr: the
// minimal CIDR cover of [low, high] (#16563), at most 62 IPv4 / 254
// IPv6 prefixes for any range, so no host-count cap applies here —
// the NAT-pool per-host cap stays on expandAddressRange's NAT and
// proxy-arp callers only. Malformed ranges (bad endpoint, non-host
// mask, mixed family, reversed) are recorded in OversizedRange
// rather than failing compilation, so the tolerant path stays
// bootable (#8814 shape); strict commit rejects the record.
func applyRangeAddress(addr *Address, low, high string) {
	noteAddressFormConflict(addr, "range-address")
	if low == "" || high == "" {
		addr.UnimplementedForms = appendUniqueForm9524(addr.UnimplementedForms, "range-address")
		return
	}
	addr.RangeSpec = low + " to " + high
	expanded, err := expandAddressRangeToCIDRCover(low, high)
	if err != nil {
		addr.OversizedRange = fmt.Sprintf("%s to %s: %v", low, high, err)
		return
	}
	addr.ExpandedPrefixes = expanded
}

// applyWildcardAddress records a wildcard-address expansion on addr.
func applyWildcardAddress(addr *Address, spec string) {
	noteAddressFormConflict(addr, "wildcard-address")
	if spec != "" {
		addr.WildcardSpec = spec
	}
	prefix, err := expandWildcardAddress(spec)
	if err != nil {
		addr.UnimplementedForms = appendUniqueForm9524(addr.UnimplementedForms, "wildcard-address")
		return
	}
	addr.ExpandedPrefixes = []string{prefix}
}

// applyDNSName records a dns-name form on addr and resolves it once.
func applyDNSName(addr *Address, fqdn, family string) {
	noteAddressFormConflict(addr, "dns-name")
	if fqdn == "" {
		addr.UnimplementedForms = appendUniqueForm9524(addr.UnimplementedForms, "dns-name")
		return
	}
	addr.DNSName = fqdn
	addr.DNSFamily = family
	resolveDNSAddressEntry(addr)
}

// noteAddressFormConflict records that a value form was authored on an
// entry already carrying a value (prefix, expansion, or dns-name). Junos
// takes exactly one form, so the combination is unimplemented as authored
// and must fail closed (#9524/#15673).
func noteAddressFormConflict(addr *Address, form string) {
	if addr.Value != "" || len(addr.ExpandedPrefixes) > 0 || addr.DNSName != "" || addr.OversizedRange != "" {
		addr.UnimplementedForms = appendUniqueForm9524(addr.UnimplementedForms, form)
	}
}

// rangeKeys extracts (low, high) from a hierarchical range-address child's
// keys/children: `range-address <low> { to { <high>; } }` arrives as a node
// Keys=[range-address low] with child [to] -> child [high], or packed
// Keys=[range-address low to high].
func rangeKeys(sub *Node) (low, high string) {
	if len(sub.Keys) >= 2 {
		low = sub.Keys[1]
	}
	if len(sub.Keys) >= 4 && sub.Keys[2] == "to" {
		high = sub.Keys[3]
		return low, high
	}
	for _, c := range sub.Children {
		if c.Name() == "to" {
			if len(c.Keys) >= 2 {
				high = c.Keys[1]
			}
			for _, cc := range c.Children {
				if len(cc.Keys) >= 1 {
					high = cc.Keys[0]
				}
			}
		} else if len(c.Keys) >= 1 && high == "" {
			high = c.Keys[0]
		}
	}
	return low, high
}

// dnsKeys extracts (fqdn, family) from a dns-name node: flat
// Keys=[... dns-name fqdn [ipv4-only|ipv6-only]] tail, hierarchical child
// Keys=[dns-name fqdn] with optional [ipv4-only]/[ipv6-only] children or
// packed keys.
func dnsKeys(keys []string, children []*Node) (fqdn, family string) {
	if len(keys) >= 1 {
		fqdn = keys[0]
	}
	for _, k := range keys[1:] {
		if k == "ipv4-only" || k == "ipv6-only" {
			family = k
		}
	}
	for _, c := range children {
		n := c.Name()
		if n == "ipv4-only" || n == "ipv6-only" {
			family = n
		}
		if len(c.Keys) >= 1 && (c.Keys[0] == "ipv4-only" || c.Keys[0] == "ipv6-only") {
			family = c.Keys[0]
		}
	}
	return fqdn, family
}
