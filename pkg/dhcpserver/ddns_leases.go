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
// display-only parseLeaseCSVDegradable not because that parser is unfiltered —
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

// State is the Kea lease state carried across the memfile parse.
type State int

const (
	StateDefault  State = keaStateDefault
	StateDeclined State = keaStateDeclined
	StateExpired  State = keaStateExpired
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
//     absent ⇒ host-name semantics, still named.
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

// ddnsLease is one active lease in the DDNS consumer's view. The authoritative
// Kea row and all HA lease-sync fields live in keaLeaseRow instead.
type ddnsLease struct {
	Family      int
	Address     string
	Identity    string // v4: client-id||hwaddr ; v6: DUID/IAID
	SubnetID    string
	HostName    string // host-name option
	ClientFQDN  string // client-supplied FQDN option (fqdn_fwd implied)
	LeaseType   int    // v6 Kea lease type; unknown values fail closed in DDNS
	LeaseTypeOK bool   // false ⇒ lease_type column present but unparseable
}

// Kea memfile lease_type column values (v6 only).
const (
	keaLeaseTypeIANA = 0
	keaLeaseTypeIATA = 1
	keaLeaseTypeIAPD = 2
)

// keaLeaseRowAccum retains the last authoritative row per address across the
// selected LFC file set. A zero row is a tombstone (inactive/expired); order
// preserves first appearance for stable output.
type keaLeaseRowAccum struct {
	latest  map[string]keaLeaseRow
	order   []string
	inOrder map[string]struct{}
}

func newKeaLeaseRowAccum() *keaLeaseRowAccum {
	return &keaLeaseRowAccum{
		latest:  map[string]keaLeaseRow{},
		inOrder: map[string]struct{}{},
	}
}

func (a *keaLeaseRowAccum) note(addr string) {
	if _, ok := a.inOrder[addr]; !ok {
		a.inOrder[addr] = struct{}{}
		a.order = append(a.order, addr)
	}
}

// parseLeaseRowSet reads and merges authoritative rows from the selected Kea
// LFC file set. `path` is the CURRENT lease file; #5796 selects the completed
// file when present, otherwise previous `.2`, input `.1`, and current, then
// merges them with Kea's append-only last-row-wins semantics.
//
// The #1387/Codex fail-safe is preserved across the set: any existing file
// that is headerless, has a mangled header, or contains a ragged row makes the
// whole family untrusted. Trusted-empty is returned only when every selected
// existing file validates and the merged active set is empty.
func parseLeaseRowSet(path string, family int, now time.Time, includeDeclined bool) (*keaLeaseRowAccum, error) {
	allPaths := keaLFCLeaseFileSetPaths(path)
	before := leaseSetIdentity(allPaths)
	paths := keaLFCLeaseFilePathsFromIdentity(allPaths, before)
	acc := newKeaLeaseRowAccum()
	prevFn := parseLeaseFileFn
	for _, f := range paths {
		var err error
		if !includeDeclined && prevFn != nil {
			err = prevFn(f, family, now, acc)
		} else {
			err = parseLeaseFile(f, family, now, acc, includeDeclined)
		}
		if err != nil {
			return nil, err
		}
	}
	if after := leaseSetIdentity(allPaths); !leaseSetIdentityStable(before, after) {
		return nil, fmt.Errorf(
			"kea lease file set rotated during read (%s): a successful kea-lfc swap "+
				"landed mid-read, so the merged set may be missing every lease appended "+
				"since the last compaction \u2014 refusing to treat it as authoritative "+
				"(#8597)", path)
	}
	return acc, nil
}

func parseActiveLeases(path string, family int, now time.Time) ([]ddnsLease, error) {
	acc, err := parseLeaseRowSet(path, family, now, false)
	if err != nil {
		return nil, err
	}
	out := make([]ddnsLease, 0, len(acc.order))
	for _, addr := range acc.order {
		row, ok := acc.latest[addr]
		if !ok || row.Address == "" {
			continue
		}
		out = append(out, row.toDDNS())
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// parseSyncLeases returns active leases plus declined (state=1) rows with
// remaining probation for lease sync (#16856). Expired-reclaimed (state=2)
// rows remain tombstones.
func parseSyncLeases(path string, family int, now time.Time) ([]keaLeaseRow, error) {
	acc, err := parseLeaseRowSet(path, family, now, true)
	if err != nil {
		return nil, err
	}
	out := make([]keaLeaseRow, 0, len(acc.order))
	for _, addr := range acc.order {
		row, ok := acc.latest[addr]
		if !ok || row.Address == "" {
			continue
		}
		out = append(out, row)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func parseLeaseFile(path string, family int, now time.Time, acc *keaLeaseRowAccum, includeDeclined bool) error {
	return parseActiveLeasesFileIntoMode(path, family, now, acc, includeDeclined)
}

// parseActiveLeasesFileInto parses ONE Kea LFC-set file into acc, applying the
// per-file fail-safe validation. A genuinely-missing file is skipped (nil
// error). An EXISTING file that is anomalous (headerless / mangled-header /
// ragged row) returns an error so the whole family is treated as untrusted.
func parseActiveLeasesFileInto(path string, family int, now time.Time, acc *keaLeaseRowAccum) error {
	return parseActiveLeasesFileIntoMode(path, family, now, acc, false)
}

func parseActiveLeasesFileIntoMode(path string, family int, now time.Time, acc *keaLeaseRowAccum, includeDeclined bool) error {
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

		// State: active rows always kept. Declined (state=1) rows are kept
		// only for lease sync (#16856) with remaining probation; state=2
		// and expired rows remain tombstones. DDNS (includeDeclined=false)
		// never publishes declined rows.
		rowState := StateDefault
		if s := get(fields, "state"); s != "" {
			if st, e := strconv.Atoi(s); e == nil {
				rowState = State(st)
			}
		}
		if rowState != StateDefault && !(includeDeclined && rowState == StateDeclined) {
			acc.latest[addr] = keaLeaseRow{}
			continue
		}
		var expire int64
		if e := get(fields, "expire"); e != "" {
			if v, err := strconv.ParseInt(e, 10, 64); err == nil {
				expire = v
			}
		}
		if expire > 0 && now.Unix() >= expire {
			acc.latest[addr] = keaLeaseRow{}
			continue
		}
		// valid_lifetime is present in both families; recover it for v4 too
		// so merged-lease recency (moreRecentGrant9791) is exact on the
		// memfile fallback, and for declined probation re-anchoring.
		validLifetime := 0
		if vl := get(fields, "valid_lifetime"); vl != "" {
			if v, e := strconv.Atoi(strings.TrimSpace(vl)); e == nil {
				validLifetime = v
			}
		}
		row := keaLeaseRow{
			Family:        family,
			Address:       addr,
			HWAddress:     get(fields, "hwaddr"),
			ClientID:      get(fields, "client_id"),
			DUID:          get(fields, "duid"),
			IAIDRaw:       get(fields, "iaid"),
			IAIDOK:        true,
			LeaseType:     "IA_NA",
			LeaseTypeOK:   true,
			PrefixLen:     0,
			SubnetIDRaw:   get(fields, "subnet_id"),
			Hostname:      get(fields, "hostname"),
			FQDNFwd:       keaCSVFlag(get(fields, "fqdn_fwd")),
			FQDNRev:       keaCSVFlag(get(fields, "fqdn_rev")),
			Expire:        expire,
			ValidLifetime: validLifetime,
			State:         rowState,
		}
		if row.SubnetIDRaw != "" {
			if sid, err := strconv.ParseUint(row.SubnetIDRaw, 10, 32); err == nil {
				row.SubnetID = int(sid)
			}
		}
		if row.IAIDRaw != "" {
			iaid, err := strconv.ParseUint(row.IAIDRaw, 10, 32)
			if err == nil {
				row.IAID = uint32(iaid)
			} else {
				row.IAIDOK = false
			}
		}
		if family == 6 {
			// lease_type / prefix_len are OPTIONAL columns. Missing lease_type
			// remains IA_NA for old memfiles; malformed values stay marked so the
			// HA projection can fail closed and the DDNS view can reject unknowns.
			if lt := get(fields, "lease_type"); lt != "" {
				if v, err := strconv.Atoi(strings.TrimSpace(lt)); err == nil {
					if kind, ok := keaLeaseTypeToString(v); ok {
						row.LeaseType = kind
					} else {
						row.LeaseType = strconv.Itoa(v)
					}
				} else {
					row.LeaseTypeOK = false
				}
			}
			if pl := get(fields, "prefix_len"); pl != "" {
				if v, err := strconv.Atoi(strings.TrimSpace(pl)); err == nil {
					row.PrefixLen = v
				}
			}
			if pf := get(fields, "pref_lifetime"); pf != "" {
				if v, err := strconv.Atoi(strings.TrimSpace(pf)); err == nil {
					row.PrefLifetime = v
					row.PrefLifetimeOK = true
				}
			}
		}
		acc.latest[addr] = row
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
func keaCSVFlag(value string) bool {
	v, err := strconv.Atoi(value)
	return err == nil && v != 0
}

// familyLabel renders a family number for error messages.
func familyLabel(family int) string {
	if family == 6 {
		return "v6"
	}
	return "v4"
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
