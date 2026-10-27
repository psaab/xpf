package config

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"
)

// #17074: the scheduler generation fingerprint must cover every field
// of SchedulerConfig and SchedulerDayWindow. The daemon previously
// hand-enumerated the fields in another package; a new field added to
// either struct silently stayed out of the hash and the apply fast
// path reused the previous generation's active state (the #12822
// near-miss dropped AllDay this way). These tests fail when a field is
// added to either struct without extending Fingerprint (or the
// explicitly empty exclusion allowlist below), and they also catch a
// field that Fingerprint writes but that flipping cannot change — a
// write of a zero-only value would be enumerated yet blind.
//
// Class: U (hermetic — pure reflection over in-memory structs, no
// kernel, daemon, or network access).

// schedulerFingerprintExcludedFields17074 names fields deliberately
// left out of the fingerprint. Today it is empty: every field of both
// structs is content the scheduler generation depends on. Excluding a
// field requires a comment here explaining why its change must not
// force a re-prime.
var schedulerFingerprintExcludedFields17074 = map[string]bool{}

func schedulerConfigHash17074(c *SchedulerConfig) [sha256.Size]byte {
	h := sha256.New()
	c.Fingerprint(h)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func schedulerDayWindowHash17074(d *SchedulerDayWindow) [sha256.Size]byte {
	h := sha256.New()
	d.Fingerprint(h)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// setNonZeroField17074 sets field i of the struct pointed to by ptr
// to a non-zero value appropriate to its kind and reports whether it
// could. The Days map gets a populated per-day window so the nested
// SchedulerDayWindow fingerprint is exercised too.
func setNonZeroField17074(t *testing.T, ptr reflect.Value, i int) {
	t.Helper()
	f := ptr.Elem().Field(i)
	switch f.Kind() {
	case reflect.String:
		f.SetString("17074-probe")
	case reflect.Bool:
		f.SetBool(true)
	case reflect.Map:
		f.Set(reflect.ValueOf(map[string]*SchedulerDayWindow{
			"monday": {StartTime: "01:00", StopTime: "02:00", AllDay: true},
		}))
	default:
		t.Fatalf("field %s has kind %s: extend setNonZeroField17074 and Fingerprint together",
			ptr.Elem().Type().Field(i).Name, f.Kind())
	}
}

// assertEveryFieldFingerprinted17074 mutates each non-excluded field
// of a fresh zero struct in turn and requires the fingerprint to
// change. A newly added field fails twice over: it is not on the
// exclusion allowlist, and (unless Fingerprint grew with it) flipping
// it leaves the hash unchanged.
func assertEveryFieldFingerprinted17074[T any](t *testing.T, name string, hash func(*T) [sha256.Size]byte) {
	t.Helper()
	typ := reflect.TypeOf((*T)(nil)).Elem()
	base := hash(new(T))
	for i := range typ.NumField() {
		field := typ.Field(i)
		if schedulerFingerprintExcludedFields17074[name+"."+field.Name] {
			continue
		}
		mutated := new(T)
		setNonZeroField17074(t, reflect.ValueOf(mutated), i)
		if got := hash(mutated); got == base {
			t.Errorf("%s.%s: setting a non-zero value did not change the fingerprint — "+
				"extend Fingerprint in scheduler_fingerprint.go (or, if the field "+
				"must not force a scheduler re-prime, add it to "+
				"schedulerFingerprintExcludedFields17074 with a justification)",
				name, field.Name)
		}
	}
}

func TestSchedulerConfigFingerprintCoversEveryField17074(t *testing.T) {
	assertEveryFieldFingerprinted17074[SchedulerConfig](t, "SchedulerConfig", schedulerConfigHash17074)
	// The Days mutation above must also move the config fingerprint
	// through the nested window: same day key, different window body.
	a := &SchedulerConfig{Name: "S", Days: map[string]*SchedulerDayWindow{
		"monday": {StartTime: "01:00", StopTime: "02:00"},
	}}
	b := &SchedulerConfig{Name: "S", Days: map[string]*SchedulerDayWindow{
		"monday": {StartTime: "01:00", StopTime: "03:00"},
	}}
	if schedulerConfigHash17074(a) == schedulerConfigHash17074(b) {
		t.Error("changing a per-day window body must change the SchedulerConfig fingerprint")
	}
	// Determinism: map iteration order must not leak into the hash.
	c := &SchedulerConfig{Name: "S", Days: map[string]*SchedulerDayWindow{
		"tuesday": {AllDay: true},
		"monday":  {Exclude: true},
	}}
	for range 8 {
		if schedulerConfigHash17074(c) != schedulerConfigHash17074(c) {
			t.Fatal("SchedulerConfig fingerprint is not deterministic")
		}
	}
}

func TestSchedulerDayWindowFingerprintCoversEveryField17074(t *testing.T) {
	assertEveryFieldFingerprinted17074[SchedulerDayWindow](t, "SchedulerDayWindow", schedulerDayWindowHash17074)
}

// The fingerprint deliberately streams into any io.Writer; the byte
// stream (not only the digest) must react to a field flip so callers
// hashing with a different digest still see the change.
func TestSchedulerFingerprintStreamReactsToField17074(t *testing.T) {
	var a, b bytes.Buffer
	(&SchedulerConfig{Name: "S"}).Fingerprint(&a)
	(&SchedulerConfig{Name: "S", AllDay: true}).Fingerprint(&b)
	if bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("toggling AllDay must change the fingerprint byte stream")
	}
	var nilCfg bytes.Buffer
	var nilPtr *SchedulerConfig
	nilPtr.Fingerprint(&nilCfg)
	if nilCfg.Len() == 0 {
		t.Fatal("nil SchedulerConfig must fingerprint as the \"<nil>\" marker, not empty")
	}
}
