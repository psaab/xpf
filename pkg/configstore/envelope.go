package configstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrConfigDBUnreadable tags a Store.Load failure caused by a PRESENT but
// unreadable active.json — a JSON parse error, a decrypt failure, or a
// config compatibility envelope that this build cannot read (too-new
// min-reader / format). It is distinct from an absent DB (start-fresh) and
// from a compile error (ErrConfigCompile, below). The daemon makes this
// FATAL at startup so an unparseable or too-new DB is never silently
// overwritten by a blind bootstrap (#1917 increment B, plan §6.4 / D1
// fatal-on-parse).
var ErrConfigDBUnreadable = errors.New("config DB present but unreadable")

// ErrConfigCompile tags a Store.Load failure where a PRESENT active.json
// read+parsed fine but the persisted tree failed to COMPILE (even through
// the tolerant compileTreeLenient path). It is distinct from
// ErrConfigDBUnreadable (the bytes were fine) and from an absent DB
// (start-fresh, no error).
//
// This is the #1960 fail-closed signal: a previously-committed config that
// no longer compiles must NOT silently fall back to positional claim-all
// interface naming. The daemon distinguishes this case with errors.Is so it
// can refuse takeover and enter the #1922 bootstrap/lifeline safe state
// (mgmt preserved, no claim-all, control plane up) instead of treating the
// store as "no active config => normal boot". A daemon hard-exit is the
// wrong remedy: it also strands management, which this sentinel exists to
// avoid. See pkg/daemon/daemon_run.go.
var ErrConfigCompile = errors.New("config DB present but does not compile")

// ErrConfigAbsentWithHistory tags a Store.Load failure where active.json is
// ABSENT but rollback/.configdb markers survive — numbered text rollback
// slots, DB rollback slots, or a pending commit-confirmed record (#10297).
// Every commit pushes the pre-commit tree into the rollback history, so such
// markers prove the box previously committed: this is a deleted/lost DB, not
// a never-booted store. It is distinct from an absent DB with no markers
// (start-fresh, no error), from ErrConfigDBUnreadable (present but unreadable
// bytes), and from ErrConfigCompile (present bytes that no longer compile).
//
// This is the #10297 fail-closed signal: silently re-importing the
// never-rewritten day-0 xpf.conf here would commit over the surviving history
// and delete it. The daemon distinguishes this case with errors.Is so it can
// refuse the import and the interface takeover, enter the #1922
// bootstrap/lifeline safe state with the loaded history available for
// explicit recovery (`rollback N` or a re-import followed by
// `commit confirmed`), instead of treating the store as fresh. A daemon
// hard-exit is the wrong remedy for the same reason as ErrConfigCompile: it
// would strand management, which this sentinel exists to avoid.
var ErrConfigAbsentWithHistory = errors.New("config DB absent but rollback history survives")

// ErrConfigLocked tags an EnterConfigure/EnterConfigureSession failure caused
// by the candidate already being held by another session (an interactive
// `configure`, a REST/gRPC config session, or another non-interactive
// committer). It is a TRANSIENT condition — the lock is released when the
// holder commits or exits — so callers that can defer should retry rather
// than drop. The event-options engine's action worker uses errors.Is to
// distinguish a held lock (retry with bounded backoff) from a permanent
// failure such as a read-only secondary (#2157). The plain-text message is
// preserved for operators that grep logs; only the error VALUE is new.
var ErrConfigLocked = errors.New("configuration is locked by another user")

// ErrClusterReadOnly tags a rejected config mutation on a cluster node that
// is NOT the RG0 primary (a read-only secondary; config authority is the
// primary). It is returned both at the EnterConfigure* gate AND on every
// user-session mutating op (Set/Delete/Commit/Load/Rollback and the
// interactive structural edits), so a config session that was opened BEFORE
// the node became secondary — or reached via a path that did not re-check —
// cannot Set+Commit and diverge the secondary's active config from the
// primary (#3893). It is a PERMANENT condition (unlike the transient
// ErrConfigLocked): the node stays read-only until it is promoted to RG0
// primary. The internal HA-sync ingress (Store.SyncApply) and the
// commit-confirmed timeout revert (Store.PromoteRollback) do NOT route
// through the gated methods, so they deliberately bypass this gate.
var ErrClusterReadOnly = errors.New("configuration is read-only on the cluster secondary")

// ErrConfigLockedByOther tags a rejected candidate mutation/commit made by a
// session that is NOT the current config-lock holder (#5059). The candidate is
// intentionally singular and shared, so serialization under Store.mu alone is
// not authorization: without this gate a session that never entered config mode
// could Set/Delete/Load/Rollback/Commit another session's pending candidate. It
// is returned by the session-scoped *As mutators and EnsureConfigHolder when a
// non-empty caller session differs from the recorded holder. A caller session
// of "" is the explicit internal/system capability (daemon apply, REST-stateless
// enter, HA sync, tests) and bypasses the gate; a lock acquired with no recorded
// holder (the internal/local EnterConfigure path) is likewise not owned by any
// session and is not blocked. It is a TRANSIENT condition (the holder commits or
// exits), so deferrable callers may errors.Is + retry.
var ErrConfigLockedByOther = errors.New("configuration candidate is held by another session")

// Config-DB compatibility envelope (#1917 increment B, plan §6.4 / D1).
//
// The envelope is EMBEDDED in active.json as a single magic header LINE
// prepended to the (possibly-encrypted) JSON body, NOT a sidecar manifest
// and NOT a wrapping JSON object. The encoding is deliberately one the
// CURRENT pre-envelope reader REJECTS rather than silently empty-loads:
//
//   - the pre-envelope reader runs json.Unmarshal(data, &ConfigTree{})
//     (db.go readTree) — a leading '#' line is NOT valid JSON, so it
//     ERRORS. Paired with fatal-on-parse (daemon_run.go), an old reader
//     fails closed on a too-new DB instead of overwriting it.
//   - a {manifest,tree} JSON OBJECT would empty-load on the old reader
//     (Go ignores unknown fields), silently wiping config. That is the
//     defect this floor closes (rev-8 codex-review-010, SMR-proven).
//
// On-disk layout of an enveloped active.json:
//
//	#xpf-config-envelope v=1 writer=<ver> ast=<n> min-reader=<n> rollback-fmt=<n>\n
//	{ ...the existing (possibly AES-GCM-encrypted) JSON body... }
//
// The header line is the OUTERMOST framing: it wraps the encrypted bytes
// for a write and is stripped BEFORE decryption on a read, so an old
// reader sees the '#' before either its decrypt-or-passthrough fallback
// or its json.Unmarshal — both reject it.
//
// A body with NO leading '#' is a pre-envelope (legacy) DB; the floor
// release still reads it (back-compat), so upgrading TO the floor release
// is non-destructive.

const (
	// envelopeMagic is the fixed token that opens the header line. The
	// leading '#' is load-bearing: it is what makes the old reader's
	// json.Unmarshal fail closed.
	envelopeMagic = "#xpf-config-envelope"

	// EnvelopeFormatVersion is the envelope grammar version (the `v=`
	// field). Bump only on an incompatible header-grammar change; a
	// reader rejects an envelope whose v= it does not understand.
	// #7176 (C179-053) raised this 1 -> 2. v2 binds the header line into the
	// AES-GCM AAD, so the plaintext header — including the #1922
	// committed= marker — is authenticated instead of freely editable.
	EnvelopeFormatVersion = 2

	// EnvelopeASTVersion is the current config AST/schema version the
	// writer stamps. Informational today (carried for future migrations);
	// not gated on read.
	EnvelopeASTVersion = 1

	// EnvelopeMinReaderVersion is the minimum envelope-format version a
	// reader must support to safely load a DB this build writes. A reader
	// whose EnvelopeFormatVersion < the stored min-reader fails closed.
	// It equals EnvelopeFormatVersion today (this build both writes and
	// requires v1); a future incompatible writer raises it.
	EnvelopeMinReaderVersion = 1

	// envelopeAADFormatVersion is the first envelope version whose encrypted
	// body is sealed with the header line as AES-GCM additional authenticated
	// data (#7176 C179-053).
	//
	// It is a READ-SIDE gate, and that is what makes the migration safe against
	// a forced downgrade. A reader uses nil AAD only when the stored v= is
	// BELOW this. An attacker who rewrites a v2 envelope's header to v=1 to get
	// the weaker path makes the reader attempt nil-AAD decryption against a
	// ciphertext sealed WITH AAD — which fails. The downgrade attempt fails
	// CLOSED rather than succeeding weakly, and the upgrade direction cannot be
	// forged because it requires re-sealing. Old envelopes stay readable and
	// migrate to v2 on their next write, so there is no flag day.
	envelopeAADFormatVersion = 2

	// EnvelopeRollbackFormatVersion is the rollback-slot DB format version
	// (carried so a future rollback-format change is detectable). The
	// auto-rollback DB-restore path (xpf-upgrade) keys binary+DB atomic
	// rollback on this matching.
	EnvelopeRollbackFormatVersion = 1
)

// committedFieldKey is the envelope header field that records whether the
// active.json on disk represents a SUCCESSFULLY-COMMITTED config
// (committed=1) or a never-successfully-committed marker (committed=0)
// written by the #1922 Item 1b first-commit rollback (`enterBootstrapMode`).
// It is the #1922 Item 2 step-0 marker.
//
// Migration rule (C3, mandatory): a DB written by an OLDER build lacks this
// field. The reader MUST default a MISSING field to committed=TRUE — an
// upgraded box with an existing active config can NEVER misclassify into
// bootstrap. The never-committed marker is therefore FORWARD-ONLY: only a DB
// this build itself wrote with committed=0 ever reads never-committed.
const committedFieldKey = "committed"

// envelopeHeader is the parsed content of the magic header line.
type envelopeHeader struct {
	FormatVersion  int
	Writer         string
	ASTVersion     int
	MinReader      int
	RollbackFormat int

	// Committed records the #1922 step-0 marker. It defaults to TRUE — a
	// header that omits the committed= field (an older-build DB, or any
	// pre-#1922 envelope) reads as committed so an upgrade can never
	// misclassify a populated active config into bootstrap (migration rule
	// C3). Only an explicit `committed=0` written by this build's
	// never-committed marker path reads false.
	Committed bool
}

// EnvelopeCompatibility is the portion of an on-disk envelope header needed
// by an upgrade rollback preflight. It intentionally omits the writer and AST
// metadata: rollback policy compares only the envelope grammar and minimum
// reader floors.
type EnvelopeCompatibility struct {
	FormatVersion int
	MinReader     int
}

// InspectEnvelopeHeader parses an envelope header without applying this
// package's current-reader gate. Callers that need to compare a snapshot
// against a different target reader (for example, an older rollback binary)
// must inspect first and apply that target-specific policy themselves.
//
// A legacy, pre-envelope body returns (zero, false, nil). A body beginning
// with the envelope magic is parsed strictly; malformed headers return an
// error so destructive callers can refuse before mutation.
func InspectEnvelopeHeader(data []byte) (EnvelopeCompatibility, bool, error) {
	if !hasEnvelope(data) {
		return EnvelopeCompatibility{}, false, nil
	}
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return EnvelopeCompatibility{}, true,
			fmt.Errorf("config envelope: header line has no terminating newline")
	}
	headerLine := strings.TrimRight(string(data[:nl]), "\r")
	hdr, err := parseEnvelopeHeader(headerLine)
	if err != nil {
		return EnvelopeCompatibility{}, true, err
	}
	return EnvelopeCompatibility{
		FormatVersion: hdr.FormatVersion,
		MinReader:     hdr.MinReader,
	}, true, nil
}

// hasEnvelope reports whether data begins with the envelope magic line.
func hasEnvelope(data []byte) bool {
	return bytes.HasPrefix(data, []byte(envelopeMagic))
}

// buildEnvelopeHeaderLine renders the magic header line (including the
// trailing newline) for the given writer version. committed stamps the
// #1922 step-0 marker (committed=1 for a real commit/sync, committed=0 for
// the never-committed first-commit-rollback marker).
func buildEnvelopeHeaderLine(writer string, committed bool, minReader int) []byte {
	if writer == "" {
		writer = "unknown"
	}
	// writer is a build version string; strip any whitespace/newline so it
	// can never break the single-line header grammar.
	writer = sanitizeEnvelopeToken(writer)
	c := 0
	if committed {
		c = 1
	}
	line := fmt.Sprintf("%s v=%d writer=%s ast=%d min-reader=%d rollback-fmt=%d %s=%d\n",
		envelopeMagic, EnvelopeFormatVersion, writer,
		EnvelopeASTVersion, minReader, EnvelopeRollbackFormatVersion,
		committedFieldKey, c)
	return []byte(line)
}

// sanitizeEnvelopeToken removes whitespace from a header token value so a
// malformed writer-version string cannot inject a newline or split the
// key=value grammar.
func sanitizeEnvelopeToken(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return '-'
		default:
			return r
		}
	}, s)
}

// wrapEnvelope prepends the magic header line to body. body is the
// already-(maybe-)encrypted JSON bytes. committed stamps the #1922 step-0
// marker (see buildEnvelopeHeaderLine).
func wrapEnvelope(body []byte, writer string, committed bool, minReader int) []byte {
	header := buildEnvelopeHeaderLine(writer, committed, minReader)
	out := make([]byte, 0, len(header)+len(body))
	out = append(out, header...)
	out = append(out, body...)
	return out
}

// stripEnvelope validates the magic header line, enforces the min-reader
// gate, and returns the body bytes (everything after the first newline).
// The caller MUST have confirmed hasEnvelope(data) first.
//
// A reader that does not understand the stored envelope (v= too new, or
// min-reader > this build's EnvelopeFormatVersion) returns an error so the
// daemon FAILS CLOSED rather than misreading a too-new DB.
func stripEnvelope(data []byte) ([]byte, *envelopeHeader, error) {
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return nil, nil, fmt.Errorf("config envelope: header line has no terminating newline")
	}
	headerLine := strings.TrimRight(string(data[:nl]), "\r")
	body := data[nl+1:]

	hdr, err := parseEnvelopeHeader(headerLine)
	if err != nil {
		return nil, nil, err
	}

	// Min-reader gate: a DB stamped min-reader=N can only be read by a
	// build whose envelope-format support is >= N. Too-new => fail closed.
	if hdr.MinReader > EnvelopeFormatVersion {
		return nil, nil, fmt.Errorf(
			"config envelope requires reader format >= %d but this build supports %d; "+
				"the config DB was written by a NEWER xpf and cannot be safely read "+
				"(upgrade xpf, or roll the binary forward); refusing to load to avoid "+
				"silently misreading or overwriting the config",
			hdr.MinReader, EnvelopeFormatVersion)
	}
	// Defense-in-depth: also reject an envelope grammar version we do not
	// understand even if min-reader were (wrongly) low.
	if hdr.FormatVersion > EnvelopeFormatVersion {
		return nil, nil, fmt.Errorf(
			"config envelope format v=%d is newer than this build supports (v=%d); refusing to load",
			hdr.FormatVersion, EnvelopeFormatVersion)
	}

	return body, hdr, nil
}

// parseEnvelopeHeader parses the magic header line into an envelopeHeader.
func parseEnvelopeHeader(line string) (*envelopeHeader, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != envelopeMagic {
		return nil, fmt.Errorf("config envelope: malformed header line %q", line)
	}
	// Default committed=true (migration rule C3): a header that omits the
	// committed= field is an older-build envelope and must read as a
	// successfully-committed config so an upgrade never misclassifies into
	// bootstrap. Only an explicit committed=0 flips this.
	hdr := &envelopeHeader{Committed: true}
	seenVersion := false
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return nil, fmt.Errorf("config envelope: malformed header field %q", f)
		}
		switch k {
		case "v":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("config envelope: bad v=%q: %w", v, err)
			}
			hdr.FormatVersion = n
			seenVersion = true
		case "writer":
			hdr.Writer = v
		case "ast":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("config envelope: bad ast=%q: %w", v, err)
			}
			hdr.ASTVersion = n
		case "min-reader":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("config envelope: bad min-reader=%q: %w", v, err)
			}
			hdr.MinReader = n
		case "rollback-fmt":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("config envelope: bad rollback-fmt=%q: %w", v, err)
			}
			hdr.RollbackFormat = n
		case committedFieldKey:
			// #7176 (C179-053): CANONICAL parse. This was strconv.Atoi followed
			// by `n != 0`, which accepted "2", "-1", "+1", "007" and " 1" as
			// committed — a permissive reading of a field that gates the #1922
			// bootstrap decision. Only the two values this build ever writes are
			// accepted; anything else is a malformed envelope, not a truthy one.
			//
			// Absence is a SEPARATE question and is deliberately NOT changed
			// here: a header with no committed= field still defaults to true
			// (migration rule C3 above), because an older-build envelope must
			// read as committed or an upgrade misclassifies into bootstrap.
			// That default stops being a fail-open once v2 binds the header into
			// the AAD, since an attacker can no longer DELETE the field without
			// breaking decryption.
			switch v {
			case "0":
				hdr.Committed = false
			case "1":
				hdr.Committed = true
			default:
				return nil, fmt.Errorf(
					"config envelope: bad %s=%q (want exactly \"0\" or \"1\")",
					committedFieldKey, v)
			}
		default:
			// Unknown fields are tolerated (additive forward-compat); the
			// v=/min-reader gate is what governs readability.
		}
	}
	if !seenVersion {
		return nil, fmt.Errorf("config envelope: header missing required v= field: %q", line)
	}
	return hdr, nil
}

// envelopeHeaderLineBytes returns the header line of an enveloped file EXACTLY
// as stored, including its trailing newline — the byte sequence the writer used
// as AES-GCM AAD (#7176 C179-053).
//
// It deliberately returns the stored bytes rather than re-rendering the header
// from the parsed fields. A re-render would normalise field order, spacing and
// unknown forward-compat fields, so any writer difference would silently break
// decryption; and it would also re-authenticate a header the reader had just
// rewritten, which is the opposite of the point. The caller must have confirmed
// hasEnvelope(data).
func envelopeHeaderLineBytes(data []byte) []byte {
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return nil
	}
	return data[:nl+1]
}

// bodySHA256FieldKey names the #9898 F-035 tamper-evidence field. The writer
// stamps "body-sha256=<64 lowercase hex>" into the header line of
// UNENCRYPTED envelopes only; the reader verifies it when present and reads
// on when absent (legacy, no flag day).
//
// What it binds: SHA-256 over the stored header line (with the hash slot
// zeroed) plus the stored body bytes — so every header byte (the v=,
// min-reader, and #1922 committed= marker included) and every body byte is
// covered. A naive one-byte committed=0/1 flip, or any corruption of header
// or body that does not recompute the digest, fails closed instead of
// silently changing the boot class.
//
// What it is NOT: tamper-PROOFING. The digest is unkeyed — there is no
// secret on the unencrypted path — so a file writer who recomputes (or
// strips, or single-bit-renames, e.g. "cody-sha256=") the field bypasses it
// exactly as they could rewrite the file wholesale. Full authentication of
// the header needs master-password (#7176 AAD on the encrypted path).
//
// Encrypted envelopes deliberately carry NO field: the seal's AAD already
// binds their header (a stronger, keyed binding), and stamping one would
// break decryption — the seal is computed over the final stored header, so
// a zero-slot-then-fill would authenticate bytes that are never stored.
const bodySHA256FieldKey = "body-sha256"

// bodySHA256ZeroSlot is the placeholder the writer hashes over: the digest
// input is the header line with the value zeroed plus the body, so the
// digest covers the header without a chicken-and-egg. Exactly 64 chars.
var bodySHA256ZeroSlot = strings.Repeat("0", 64)

// slottedBodySHA256Header returns headerLine with " body-sha256=<zeros>"
// inserted before the trailing newline. headerLine must end with '\n' (every
// buildEnvelopeHeaderLine output does). fillBodySHA256 writes the digest.
func slottedBodySHA256Header(headerLine []byte) []byte {
	base := headerLine[:len(headerLine)-1]
	out := make([]byte, 0, len(base)+1+len(bodySHA256FieldKey)+1+len(bodySHA256ZeroSlot)+1)
	out = append(out, base...)
	out = append(out, ' ')
	out = append(out, bodySHA256FieldKey...)
	out = append(out, '=')
	out = append(out, bodySHA256ZeroSlot...)
	out = append(out, '\n')
	return out
}

// fillBodySHA256 replaces the zero slot in a slotted header line (see
// slottedBodySHA256Header) with the hex SHA-256 over (slotted line + body).
func fillBodySHA256(slottedLine, body []byte) []byte {
	h := sha256.New()
	h.Write(slottedLine)
	h.Write(body)
	sum := hex.EncodeToString(h.Sum(nil))
	out := make([]byte, len(slottedLine))
	copy(out, slottedLine)
	start := len(out) - len(bodySHA256ZeroSlot) - 1 // slot sits just before '\n'
	copy(out[start:], sum)
	return out
}

// verifyBodySHA256 checks the F-035 binding on a stored envelope: storedLine
// is the raw header line bytes (envelopeHeaderLineBytes, trailing newline
// included) and body is the stored body (post-strip, pre-decrypt — for the
// unencrypted envelopes that carry the field this is the plaintext).
//
// Absent field: nil (legacy envelope, read on). Present field: the value
// must be exactly 64 hex chars naming SHA-256(zeroed line + body), else the
// envelope is rejected. Duplicate fields are malformed, never "the first
// one wins". Only field-boundary matches count — "xbody-sha256=" is an
// unrelated unknown field, tolerated like any other.
func verifyBodySHA256(storedLine, body []byte) error {
	token := bodySHA256FieldKey + "="
	valStart, valEnd := -1, -1
	for i := 0; i+len(token) <= len(storedLine); {
		j := bytes.Index(storedLine[i:], []byte(token))
		if j < 0 {
			break
		}
		i += j
		// Field boundary: start of line or preceded by whitespace, so
		// "xbody-sha256=" (an unrelated unknown field) never matches.
		if i > 0 && !isHeaderSpace(storedLine[i-1]) {
			i += len(token)
			continue
		}
		vStart := i + len(token)
		vEnd := vStart
		for vEnd < len(storedLine) && !isHeaderSpace(storedLine[vEnd]) {
			vEnd++
		}
		if valStart >= 0 {
			return fmt.Errorf("config envelope: duplicate %q fields", bodySHA256FieldKey)
		}
		valStart, valEnd = vStart, vEnd
		i = vEnd
	}
	if valStart < 0 {
		return nil // no field: legacy envelope, read on
	}
	value := storedLine[valStart:valEnd]
	if len(value) != 64 {
		return fmt.Errorf("config envelope: bad %s length %d (want 64 hex chars)", bodySHA256FieldKey, len(value))
	}
	if _, err := hex.DecodeString(string(value)); err != nil {
		return fmt.Errorf("config envelope: bad %s value (want hex): %v", bodySHA256FieldKey, err)
	}
	// Reconstruct the zeroed-slot input on a copy: the stored bytes with
	// exactly the value span replaced by zeros. Everything else (field
	// order, spacing, unknown forward-compat fields) is hashed verbatim.
	slotted := make([]byte, len(storedLine))
	copy(slotted, storedLine)
	copy(slotted[valStart:], bodySHA256ZeroSlot)
	h := sha256.New()
	h.Write(slotted)
	h.Write(body)
	if got := hex.EncodeToString(h.Sum(nil)); got != string(value) {
		return fmt.Errorf("config envelope: %s mismatch — the header or body was modified "+
			"without recomputing the digest (naive edit or corruption); refusing", bodySHA256FieldKey)
	}
	return nil
}

// isHeaderSpace reports JSON/header insignificant whitespace plus CR (headers
// are single lines; CR appears only in hand-edited ones).
func isHeaderSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
