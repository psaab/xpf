package dhcpserver

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// ddns_leases.go: a STATE-AWARE Kea memfile lease parser for the #1387
// DDNS reconciler (plan §5 invariant 3). It stays SEPARATE from the
// display-only parseLeaseCSV not because that parser is unfiltered —
// since #2085 it also filters non-active state + expired rows and dedups
// per address — but because the two have opposite failure postures: this
// DDNS parser is DESTRUCTIVE (its empty result authorizes deleting owned
// DNS records), so it hard-errors on a mangled / duplicate-column /
// ragged header, validates the required columns, and carries the v6
// DUID/IAID identity the reconciler keys ownership on; the display parser
// is NON-DESTRUCTIVE and LENIENT (a bad row degrades, never blanks the
// `show`). Merging them would force one posture onto the other, so this
// parser intentionally does NOT replace the display one.

// Kea lease state column values (memfile CSV `state`).
const (
	keaStateDefault  = 0 // active
	keaStateDeclined = 1
	keaStateExpired  = 2 // expired-reclaimed
)

// requiredLeaseColumns lists, per family, the Kea memfile header columns the
// reconciler MUST be able to read to compute the desired DNS state and run a
// SAFE destructive diff. The mass-delete / record-loss class is NOT specific
// to address/state: ANY column whose absence silently changes whether a lease
// is published, how it is keyed for ownership, or whether it is active is
// destructive, because a mangled header parses with no error and the
// reconciler then deletes owned records on the basis of an empty or
// wrongly-keyed desired set. So the required set covers every such column; if
// any is MISSING from the header the parser returns an error and Reconcile
// marks the family untrusted and SKIPS the destructive diff. The fail
// direction (over-mark-untrusted for an exotic header → no publish/clean,
// operator-visible) is SAFE; silent mass-delete / record-loss is not.
//
// Required (both families):
//   - address  — keys every lease AND is the ownership key fallback; absent ⇒
//     every row reads "" ⇒ empty lease set ⇒ Pass-1 deletes all owned.
//   - state    — separates an active lease from a declined/expired-reclaimed
//     one; absent ⇒ active and tombstoned rows are indistinguishable (a
//     reclaimed/declined address would be published or a publishable one lost).
//   - hostname — the naming source; absent ⇒ deriveFQDN errors for every lease
//     ⇒ all leases skipped as unnamed ⇒ empty desired set ⇒ mass-delete
//     (MAJOR A). An empty hostname VALUE is fine; we require the COLUMN.
//
// Required (v4 identity): client_id AND hwaddr — the ownership key derives
// from client-id||hwaddr; absent ⇒ identity collapses to the address-fallback
// ⇒ owned records keyed by the prior real identity no longer match desired ⇒
// delete + re-add churn; if the delete succeeds and the re-add upsert fails
// the active record is LOST (MAJOR B).
//
// Required (v6 identity): duid AND iaid — same record-loss as v4 for the
// DUID/IAID identity.
//
// Deliberately OPTIONAL (absence degrades safely, no record loss):
//   - fqdn_fwd  — only routes the hostname value into HostName vs ClientFQDN;
//     absent ⇒ splitLeaseNames defaults to host-name semantics, still named.
//   - expire    — absent ⇒ no expiry-based tombstoning (state still gates
//     active-vs-tombstone); over-RETAIN of a stale lease, never a delete.
//   - subnet_id — pure metadata stored on the owned record; recordsEqual does
//     NOT compare it, so its absence changes no destructive computation.
//
// Names are matched case-insensitively (cols keys + get() lookups are
// lower-cased).
var requiredLeaseColumns = map[int][]string{
	4: {"address", "state", "hostname", "client_id", "hwaddr"},
	6: {"address", "state", "hostname", "duid", "iaid"},
}

// ddnsLease is one active lease as the reconciler needs it: a stable
// owner identity, the address, the offered name(s), the subnet, and the
// expiry. In addition to the packed Identity used by the DDNS reconciler,
// v4 hardware address and client-id are retained separately for the
// lease-sync memfile fallback. The packed identity is intentionally kept
// client-id-preferred for DDNS ownership stability; it is not a lossless
// transport for the two v4 columns.
type ddnsLease struct {
	Family     int // 4 or 6
	Address    string
	Identity   string // v4: client-id||hwaddr ; v6: DUID/IAID
	HWAddress  string // v4 hardware address, retained for lease sync
	ClientID   string // v4 client identifier, retained for lease sync
	SubnetID   string
	HostName   string // host-name option
	ClientFQDN string // client-supplied FQDN option (fqdn_fwd implied)
	Expire     int64  // unix epoch

	// v6 lease kind, recovered from the memfile so the #2239 lease-sync
	// fallback (readSyncLeasesViaMemfile) preserves IA_PD vs IA_NA instead of
	// mis-seeding a prefix-delegation lease as an address lease (#2262). These
	// are NOT used by the DDNS reconciler (it keys on identity+address) — the
	// fields are inert for v4 and for the DDNS path. lease_type / prefix_len
	// are OPTIONAL memfile columns (not in requiredLeaseColumns): an old
	// memfile or a v4 file leaves LeaseType == keaLeaseTypeIANA and
	// LeaseTypeOK == true, preserving the prior (hardcoded IA_NA) behavior. A
	// PRESENT but unparseable lease_type sets LeaseTypeOK == false so the sync
	// path can skip the row rather than silently mis-type it.
	LeaseType   int  // Kea numeric lease_type: 0=IA_NA, 1=IA_TA, 2=IA_PD
	LeaseTypeOK bool // false ⇒ lease_type column present but unparseable
	PrefixLen   int  // v6 IA_PD delegated prefix length (0 when absent)

	// #5073: the v6 memfile carries DISTINCT valid_lifetime and pref_lifetime
	// columns. The lease-sync memfile fallback (readSyncLeasesViaMemfile) needs
	// both to recover a clock-skew-safe preferred remaining independent of the
	// valid remaining, so a DEPRECATED binding (pref_lifetime=0) is not revived
	// on takeover. Both are OPTIONAL columns (not in requiredLeaseColumns): an
	// old memfile or a v4 file leaves them 0 with PrefLifetimeOK=false, and the
	// sync path then defaults preferred==valid. The DDNS reconciler ignores both.
	ValidLifetime  int  // memfile valid_lifetime column (seconds), 0 if absent
	PrefLifetime   int  // memfile pref_lifetime column (seconds), 0 if absent
	PrefLifetimeOK bool // true ⇒ pref_lifetime column present AND parseable
}

// Kea memfile lease_type column values (v6 only).
const (
	keaLeaseTypeIANA = 0
	keaLeaseTypeIATA = 1
	keaLeaseTypeIAPD = 2
)

// parseActiveLeases4 reads the Kea v4 memfile and returns only active
// leases (state default, not yet expired). now is the reference time for
// the expiry check (injected for tests).
func parseActiveLeases4(path string, now time.Time) ([]ddnsLease, error) {
	return parseActiveLeases(path, 4, now)
}

// parseActiveLeases6 reads the Kea v6 memfile and returns only active
// leases (state default, not yet expired).
func parseActiveLeases6(path string, now time.Time) ([]ddnsLease, error) {
	return parseActiveLeases(path, 6, now)
}

// ddnsLeaseAccum accumulates the append-only, last-row-wins disposition per
// address ACROSS the Kea LFC file set (#5796). A non-empty ddnsLease.Address is
// an active lease to publish; a zero value is a tombstone (the last row seen for
// that address, in chronological file+row order, was inactive/expired). order
// preserves first-appearance for a stable output.
type ddnsLeaseAccum struct {
	latest  map[string]ddnsLease
	order   []string
	inOrder map[string]struct{}
}

func newDDNSLeaseAccum() *ddnsLeaseAccum {
	return &ddnsLeaseAccum{
		latest:  map[string]ddnsLease{},
		inOrder: map[string]struct{}{},
	}
}

func (a *ddnsLeaseAccum) note(addr string) {
	if _, ok := a.inOrder[addr]; !ok {
		a.inOrder[addr] = struct{}{}
		a.order = append(a.order, addr)
	}
}

// parseActiveLeases reads the Kea memfile lease set for `family` and returns
// only the active leases. `path` is the CURRENT lease file; #5796: it reads
// Kea's selected LFC source set (completed,current when `.completed` exists;
// otherwise previous `.2`, input `.1`, current) via keaLFCLeaseFilePaths in
// source order and MERGES it with the same append-only, last-row-wins dedup
// Kea itself uses. A lease that currently lives only in the compacted previous
// or input file (e.g. right after LFC rotated a fresh header-only current file)
// is NOT lost and a header-only current file cannot by itself trigger the
// destructive DDNS trusted-empty path.
//
// The #1387/Codex fail-safe is preserved and EXTENDED across the set: any
// EXISTING file that is headerless / mangled-header / ragged makes the whole
// family untrusted (error → Reconcile SKIPS the destructive diff). Trusted-empty
// (nil, nil) is returned only when every selected existing file validates AND
// the merged active set is empty — a genuinely-missing generation file simply
// contributes nothing.
func parseActiveLeases(path string, family int, now time.Time) ([]ddnsLease, error) {
	allPaths := keaLFCLeaseFileSetPaths(path)
	before := leaseSetIdentity(allPaths)
	paths := keaLFCLeaseFilePathsFromIdentity(allPaths, before)

	// #8597 (muse-004 K52): the complete four-name file set is opened
	// SEQUENTIALLY, so a SUCCESSFUL kea-lfc rotation landing mid-read silently
	// drops rows unless the post-read identity check sees it.
	//
	// The snapshot includes `.completed` even when it was absent during source
	// selection. This is deliberate: a rotation can create `.completed` and
	// remove `.2`/`.1` after the selection snapshot; comparing all four names
	// afterward catches that transition and refuses a potentially incomplete
	// trusted set.
	//
	// This is NOT the case §Invariant-3 argues about. That argument is about a
	// CRASH-interrupted cleanup, where `.1` stays intact and is read, and it is
	// sound — I am not disputing it. The gap is the SUCCESSFUL rotation, where
	// `.1` is deliberately removed. Detection closes the harmful outcome
	// outright, and a skipped reconcile cycle self-heals on the next one.

	acc := newDDNSLeaseAccum()
	for _, f := range paths {
		if err := parseLeaseFileFn(f, family, now, acc); err != nil {
			return nil, err
		}
	}

	if after := leaseSetIdentity(allPaths); !leaseSetIdentityStable(before, after) {
		return nil, fmt.Errorf(
			"kea lease file set rotated during read (%s): a successful kea-lfc swap "+
				"landed mid-read, so the merged set may be missing every lease appended "+
				"since the last compaction — refusing to treat it as authoritative "+
				"(#8597)", path)
	}
	out := make([]ddnsLease, 0, len(acc.order))
	for _, addr := range acc.order {
		l, ok := acc.latest[addr]
		if !ok || l.Address == "" {
			continue // tombstoned by the FINAL inactive/expired row across the set
		}
		out = append(out, l)
	}
	if len(out) == 0 {
		// Trusted-empty: every existing file in the set validated (no error
		// above) and the merged active set is empty. Return nil (not a
		// non-nil empty slice) to match the pre-#5796 os.IsNotExist /
		// header-only trusted-empty contract the DDNS reconciler relies on.
		return nil, nil
	}
	return out, nil
}

// parseActiveLeasesFileInto parses ONE Kea LFC-set file into acc, applying the
// per-file fail-safe validation. A genuinely-missing file is skipped (nil
// error). An EXISTING file that is anomalous (headerless / mangled header /
// ragged row) returns an error so the whole family is treated as untrusted.
func parseActiveLeasesFileInto(path string, family int, now time.Time, acc *ddnsLeaseAccum) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // memfile rows vary across Kea versions
	r.Comment = '#'
	// #4886 C: stream row-by-row (r.Read) instead of csv.ReadAll(). A Kea LFC
	// memfile accumulates many historical rows between compactions; ReadAll
	// materialized ALL of them ([][]string) before reducing to acc (which keeps
	// only the latest row per address) — an O(history) transient that can OOM the
	// control plane under lease churn. Read the header first (for schema
	// validation), then fold each data row into acc as it is read: peak memory
	// O(unique addresses), not O(history). acc keeps latest-per-address, so this
	// is semantically identical to the pre-#4886 ReadAll path.
	header, err := r.Read()
	if err == io.EOF {
		// No header at all — anomalous (Kea always writes a header). Fail SAFE
		// (untrusted → Reconcile SKIPS the destructive diff), not trusted-empty.
		return fmt.Errorf("parse %s: Kea %s lease file has no header (anomalous: mid-write or corrupt)",
			path, familyLabel(family))
	}
	if err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	// Fail-safe (#1387 + Codex r4): the trusted-empty result (nil, nil) is
	// what PERMITS Reconcile to delete a family's owned records, so it must
	// be returned ONLY when we can prove the lease set is genuinely empty —
	// never when the header is unrecognizable. Order matters:
	//
	//   1. An existing-but-0-record file (no header at all) is anomalous —
	//      Kea always writes a header line when it creates the memfile, so a
	//      headerless existing file is a mid-write / truncated / corrupt read.
	//      We cannot validate columns, so fail SAFE (error → untrusted →
	//      Reconcile SKIPS the destructive diff), not trusted-empty. (A
	//      genuinely MISSING file already returned nil,nil above via
	//      os.IsNotExist — "no leases yet" is a legitimate trusted-empty.)
	//   2. A present header is ALWAYS validated BEFORE any trusted-empty
	//      return, so a mangled header (missing required column) errors even
	//      for a header-only / zero-data-row file. This closes the Codex-r4
	//      hole where len(records) < 2 short-circuited ahead of validation,
	//      re-opening the mass-delete via a header-only mangled file.
	//   3. Only AFTER the header validates as GOOD is a header-with-zero-data
	//      -rows treated as a legitimate trusted zero-lease (nil, nil): a
	//      healthy header + no active rows genuinely means "no active
	//      leases", and clearing owned DNS records is then correct.
	// Build the header->index map with CASE-INSENSITIVE keys. Kea's real
	// memfile headers are lower-case, but normalizing defends against a
	// mangled header ("Address"/"ADDRESS") silently resolving to no column.
	// Only the header KEYS and the get() lookup name are lower-cased; field
	// VALUES (addresses, identities, hostnames) are data and stay verbatim.
	//
	// DUPLICATE-column rejection (Codex r5): a name appearing more than once
	// in the header would silently OVERWRITE the earlier index with the LAST
	// occurrence, so cols[name] could point at the wrong/empty column and
	// leases would read empty/wrong → wrong desired set → the destructive
	// pass deletes owned records. A healthy Kea memfile has all-unique column
	// names, so we reject ANY duplicate column name in the header (not just
	// duplicates of the columns we read): a header is trusted only if it maps
	// UNAMBIGUOUSLY. Reject before any column lookup so an ambiguous header
	// can never drive a destructive diff. Names compared case-insensitively
	// (two "Address"/"address" columns collide).
	cols := make(map[string]int)
	for i, h := range header {
		key := strings.ToLower(strings.TrimSpace(h))
		if _, dup := cols[key]; dup {
			return fmt.Errorf("parse %s: duplicate column %q in Kea %s lease header (ambiguous)",
				path, key, familyLabel(family))
		}
		cols[key] = i
	}
	get := func(fields []string, name string) string {
		return leaseColumnValue(cols, fields, name)
	}

	// Header validation (#1387 MAJOR-4 + Codex r3 MAJOR-A/B + r4): the
	// reconciler's destructive delete pass treats an EMPTY (or wrongly-keyed)
	// desired set as ground truth. A mangled header — a required column
	// missing or renamed — parses with NO error but silently changes whether
	// leases are published (naming), how they are keyed (identity), or whether
	// they are active (state), so Reconcile would mass-delete or churn
	// (delete+re-add, losing the record on a failed re-add) owned records. So
	// any MISSING required column for this family is a hard parse error —
	// checked BEFORE the zero-data-row return so a header-only mangled file
	// also errors; Reconcile then marks the family untrusted and SKIPS the
	// destructive diff. See requiredLeaseColumns for the per-column rationale.
	var missing []string
	for _, req := range requiredLeaseColumns[family] {
		if _, ok := cols[req]; !ok {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("parse %s: missing required column(s) %v in Kea %s lease header",
			path, missing, familyLabel(family))
	}

	// Per-row conformance bound (Codex r6): the header validation above
	// guarantees the SCHEMA is sound, but a DATA ROW can still be too short
	// to actually supply a required column (FieldsPerRecord=-1 allows ragged
	// rows; a torn/truncated Kea append leaves a row that does not reach a
	// required column's index). leaseColumnValue returns "" for an
	// out-of-range index, so a ragged row would silently mis-read a required
	// column (e.g. address="" → row dropped; hostname="" → unnamed-skip),
	// dropping that lease from the desired set → its owned DNS record is
	// deleted. We cannot tell WHICH lease a torn row is, so we must NOT just
	// skip the row — that still drops its record. Instead, a row too short to
	// supply every required column makes the SOURCE unreliable for this
	// family: error → Reconcile marks the family untrusted → SKIPS the
	// destructive diff. Compute the max index among the required columns; a
	// row with len(fields) <= maxRequiredIdx cannot reliably be read.
	maxRequiredIdx := -1
	for _, req := range requiredLeaseColumns[family] {
		if idx := cols[req]; idx > maxRequiredIdx {
			maxRequiredIdx = idx
		}
	}

	// Header is present AND valid. A file with only a header (zero data rows) is
	// a LEGITIMATE trusted zero-lease contribution: the streaming loop below reads
	// zero data rows and returns nil, adding nothing to acc, so a genuinely-empty
	// file in the LFC set contributes no leases (and, alone, correctly clears
	// owned records).
	//
	// Kea appends rows; the LAST row for an address is authoritative (lease
	// renewal / state change). We keep the last seen row per address (across
	// the whole LFC file set, via acc) and emit in first-appearance order. The
	// map value carries the row's final disposition: a non-empty Address is an
	// active lease to publish, an empty (zero) value is a tombstone (the last
	// row was inactive/expired) and is filtered from the output. CRITICAL
	// (#1387 MAJOR-3): an active row must be able to RECLAIM an address that an
	// earlier row tombstoned (declined/expired/reclaimed then re-allocated), so
	// we recompute the disposition on every row and ensure the address is
	// recorded in acc.order whenever it first appears, tombstone or not. Output
	// order is stable; the tombstone filter at emit time drops still-inactive
	// ones.
	rowNum := -1
	for {
		fields, rerr := r.Read()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("parse %s: %w", path, rerr)
		}
		rowNum++
		// Row-conformance (Codex r6): a row too short to supply every
		// required column cannot be read reliably. Treat the whole family's
		// source as unreliable (torn/truncated memfile) rather than silently
		// mis-reading the row, which would drop a lease and delete its owned
		// record. A row with MORE fields than the header is fine (extra
		// trailing fields are ignored by name-based lookup). rowNum is
		// 0-based over the data rows (records[1:]); +2 gives the 1-based file
		// line number including the header.
		if len(fields) <= maxRequiredIdx {
			return fmt.Errorf("parse %s: Kea %s lease row %d has %d field(s), too short for required columns (need > %d; ragged/truncated source)",
				path, familyLabel(family), rowNum+2, len(fields), maxRequiredIdx)
		}
		addr := get(fields, "address")
		if addr == "" {
			continue
		}
		acc.note(addr)

		// State filter: only "default" (active) rows are publishable;
		// declined / expired-reclaimed rows must NOT have DNS records.
		// An unparseable/absent state is treated as active (Kea's
		// default), matching the display parser's lenient stance.
		if s := get(fields, "state"); s != "" {
			if st, e := strconv.Atoi(s); e == nil && st != keaStateDefault {
				// A non-default state for an address supersedes any earlier
				// row for it: write a tombstone (the address stays in
				// acc.order so a LATER active row can reclaim it).
				acc.latest[addr] = ddnsLease{}
				continue
			}
		}

		var expire int64
		if e := get(fields, "expire"); e != "" {
			if v, err := strconv.ParseInt(e, 10, 64); err == nil {
				expire = v
			}
		}
		// Expiry filter: a lease whose expire epoch is in the past is
		// stale regardless of state column lag. Tombstone it (a later
		// active row with a future expire can still reclaim the address).
		if expire > 0 && now.Unix() >= expire {
			acc.latest[addr] = ddnsLease{}
			continue
		}

		hostName, clientFQDN := splitLeaseNames(get(fields, "hostname"), get(fields, "fqdn_fwd"))
		l := ddnsLease{
			Family:      family,
			Address:     addr,
			SubnetID:    get(fields, "subnet_id"),
			HostName:    hostName,
			ClientFQDN:  clientFQDN,
			Expire:      expire,
			LeaseType:   keaLeaseTypeIANA, // address lease by default (v4, or v6 sans column)
			LeaseTypeOK: true,
		}
		if family == 6 {
			l.Identity = identity6(get(fields, "duid"), get(fields, "iaid"))
			// Recover the v6 lease kind so the lease-sync memfile fallback can
			// preserve IA_PD vs IA_NA (#2262). lease_type / prefix_len are
			// OPTIONAL columns: an absent or empty lease_type leaves the IA_NA
			// default (matching the prior hardcoded behavior); a PRESENT but
			// unparseable value flips LeaseTypeOK so the sync path skips the row
			// instead of mis-typing it. The DDNS reconciler ignores both fields.
			if lt := get(fields, "lease_type"); lt != "" {
				if v, e := strconv.Atoi(strings.TrimSpace(lt)); e == nil {
					l.LeaseType = v
				} else {
					l.LeaseTypeOK = false
				}
			}
			if pl := get(fields, "prefix_len"); pl != "" {
				if v, e := strconv.Atoi(strings.TrimSpace(pl)); e == nil {
					l.PrefixLen = v
				}
			}
			// #5073: recover valid_lifetime + pref_lifetime so the lease-sync
			// memfile fallback can derive a preferred remaining that does NOT
			// revive a deprecated (pref_lifetime=0) binding on takeover. Both
			// columns are OPTIONAL; an absent/unparseable pref_lifetime leaves
			// PrefLifetimeOK false so the sync path defaults preferred==valid.
			if vl := get(fields, "valid_lifetime"); vl != "" {
				if v, e := strconv.Atoi(strings.TrimSpace(vl)); e == nil {
					l.ValidLifetime = v
				}
			}
			if pf := get(fields, "pref_lifetime"); pf != "" {
				if v, e := strconv.Atoi(strings.TrimSpace(pf)); e == nil {
					l.PrefLifetime = v
					l.PrefLifetimeOK = true
				}
			}
		} else {
			l.HWAddress = get(fields, "hwaddr")
			l.ClientID = get(fields, "client_id")
			l.Identity = identity4(l.ClientID, l.HWAddress)
		}
		acc.latest[addr] = l
	}

	return nil
}

// leaseColumnValue looks up a field by header name, CASE-INSENSITIVELY. It
// lower-cases the lookup name so the case-insensitivity invariant holds at the
// call site (cols keys are already lower-cased when the map is built), not just
// because callers happen to pass lower-case literals. Field VALUES are never
// touched — only the header name is normalized. Returns "" when the column is
// absent or the row is short.
func leaseColumnValue(cols map[string]int, fields []string, name string) string {
	if idx, ok := cols[strings.ToLower(name)]; ok && idx >= 0 && idx < len(fields) {
		return fields[idx]
	}
	return ""
}

// familyLabel renders a family number for error messages.
func familyLabel(family int) string {
	if family == 6 {
		return "v6"
	}
	return "v4"
}

func splitLeaseNames(hostname, fqdnFwd string) (hostName, clientFQDN string) {
	if hostname == "" {
		return "", ""
	}
	if v, err := strconv.Atoi(fqdnFwd); err == nil && v != 0 {
		return "", hostname
	}
	return hostname, ""
}

// identity4 returns the stable v4 owner identity: client-id when present
// (RFC 2131 client identifier survives a NIC swap), else the hardware
// address. Empty inputs yield "" (the lease is then keyed on address
// only by the caller, which still cleans on reassign because the address
// is the reverse key).
func identity4(clientID, hwaddr string) string {
	if clientID != "" {
		return "cid:" + clientID
	}
	if hwaddr != "" {
		return "mac:" + hwaddr
	}
	return ""
}

// identity6 returns the stable v6 owner identity from DUID + IAID.
func identity6(duid, iaid string) string {
	if duid == "" {
		return ""
	}
	if iaid != "" {
		return "duid:" + duid + "/" + iaid
	}
	return "duid:" + duid
}

// parseLeaseFileFn is the per-file parse seam. Production is
// parseActiveLeasesFileInto; a test replaces it to make the mid-read rotation
// K52 describes DETERMINISTIC rather than raced for.
var parseLeaseFileFn = parseActiveLeasesFileInto

// leaseSetIdentity captures which of the LFC set's files exist and which inodes
// they are, so a rotation that happened during the read can be detected
// afterwards (#8597).
//
// A nil entry means "did not exist", which is a legitimate steady state for
// .1/.2 and must compare equal to itself — the point is CHANGE, not presence.
func leaseSetIdentity(paths []string) []os.FileInfo {
	out := make([]os.FileInfo, len(paths))
	for i, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue // absent, or unreadable: recorded as nil
		}
		out[i] = fi
	}
	return out
}

// leaseSetIdentityStable reports whether the LFC file set is unchanged between
// two identity snapshots.
//
// os.SameFile is the comparison rather than mtime or size: kea-lfc's swap is a
// RENAME, so the path keeps its name and gets a new inode, and a size or
// timestamp comparison can collide on a rotation that produces a same-sized
// file within the timestamp's resolution. Appearing and disappearing both
// count as change — an unlinked .1 is exactly the row-losing case.
func leaseSetIdentityStable(before, after []os.FileInfo) bool {
	if len(before) != len(after) {
		return false
	}
	for i := range before {
		switch {
		case before[i] == nil && after[i] == nil:
		case before[i] == nil || after[i] == nil:
			return false
		case !os.SameFile(before[i], after[i]):
			return false
		}
	}
	return true
}
