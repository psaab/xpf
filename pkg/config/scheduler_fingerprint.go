package config

import (
	"io"
	"sort"
)

// scheduler_fingerprint.go places the scheduler-generation fingerprint
// beside the types it hashes (#17074). policySchedulerConfigHash in
// pkg/daemon previously hand-enumerated every SchedulerConfig and
// SchedulerDayWindow field, with no completeness guard: five commits
// had to extend the two lists in lockstep, and one (#12822) silently
// dropped AllDay. Keeping the enumeration on the types removes the
// cross-package mirror; the reflection completeness test in
// scheduler_fingerprint_test.go fails on any field added to either
// struct without also extending Fingerprint (or the explicitly empty
// exclusion allowlist there).
//
// The wire format must stay byte-identical to the daemon hash it
// replaces: strings are length-prefixed (8-byte little-endian length
// followed by raw bytes), bools are a single 0/1 byte, and strings and
// bools are written field-by-field with no field labels. Callers
// therefore cannot distinguish one field's bytes from another's
// except by position — exactly as before — and a mixed-version peer
// compares generations identically.

// WriteSchedulerHashString writes s to w as an 8-byte little-endian
// length prefix followed by the raw bytes. It is the framing the
// scheduler generation hash uses for map keys and the configured
// timezone, which Fingerprint does not cover; the daemon hashes those
// through this helper so every string in the digest shares one
// framing.
func WriteSchedulerHashString(w io.Writer, s string) {
	var lenBuf [8]byte
	for i := range lenBuf {
		lenBuf[i] = byte(uint64(len(s)) >> (8 * i))
	}
	_, _ = w.Write(lenBuf[:])
	_, _ = w.Write([]byte(s))
}

func writeFramedString(w io.Writer, s string) {
	WriteSchedulerHashString(w, s)
}

func writeFramedBool(w io.Writer, b bool) {
	if b {
		_, _ = w.Write([]byte{1})
	} else {
		_, _ = w.Write([]byte{0})
	}
}

// Fingerprint writes every content field of c to w in declaration
// order: the string scalars, the bool flags, then the Days map in
// sorted key order (nil windows fingerprinted as "<nil>"). A nil
// receiver writes "<nil>", matching the daemon's nil-scheduler marker
// under its map key.
//
// hash.Hash satisfies io.Writer, so callers can stream into a running
// digest.
func (c *SchedulerConfig) Fingerprint(w io.Writer) {
	if c == nil {
		writeFramedString(w, "<nil>")
		return
	}
	writeFramedString(w, c.Name)
	writeFramedString(w, c.StartTime)
	writeFramedString(w, c.StopTime)
	writeFramedString(w, c.StartDate)
	writeFramedString(w, c.StopDate)
	writeFramedBool(w, c.Daily)
	writeFramedBool(w, c.AllDay)
	writeFramedBool(w, c.DailyExclude)
	// #16010: an Unresolvable mark changes runtime activation without
	// changing any window field, so it must force a scheduler
	// re-prime; otherwise apply would reuse the previous generation's
	// active state for a scheduler that must now fail closed.
	writeFramedBool(w, c.Unresolvable)
	dayNames := make([]string, 0, len(c.Days))
	for day := range c.Days {
		dayNames = append(dayNames, day)
	}
	sort.Strings(dayNames)
	for _, day := range dayNames {
		writeFramedString(w, day)
		c.Days[day].Fingerprint(w)
	}
}

// Fingerprint writes every content field of d to w in declaration
// order: StartTime, StopTime, AllDay, Exclude. A nil receiver writes
// "<nil>", matching the daemon's nil-window marker under its day key.
func (d *SchedulerDayWindow) Fingerprint(w io.Writer) {
	if d == nil {
		writeFramedString(w, "<nil>")
		return
	}
	writeFramedString(w, d.StartTime)
	writeFramedString(w, d.StopTime)
	writeFramedBool(w, d.AllDay)
	writeFramedBool(w, d.Exclude)
}
