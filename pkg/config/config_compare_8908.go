package config

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ConfigFingerprint returns a stable SHA-256 digest of a canonical rendering.
// Use it to compare compiled Config values structurally.
//
// USE THIS INSTEAD OF fmt.Sprintf("%v", cfg) OR reflect.DeepEqual.
//
// The Config graph is full of pointers, so `%v` and `%+v` print ADDRESSES for
// every nested struct, map value and slice element. Two structurally identical
// configs therefore render DIFFERENTLY on every compile, and two structurally
// different ones can render identically if the difference is behind a pointer
// whose address happens to repeat.
//
// The failure is silent and it is STABLE, which is what makes it dangerous: a
// comparison built on `%v` reports a difference every run, so re-running
// confirms it. Repeat-run stability is a check against non-determinism and
// nothing else.
//
// This has cost this codebase three separate wrong measurements:
//   - a NAT sampling row filed as a defect because map[string]*SamplingInstance
//     printed addresses (the row is not a defect);
//   - a leaf-contingency guard that reported ZERO contingent pairs against the
//     sweep's seven, because every site compared unequal and so every pair
//     agreed;
//   - and the same trap documented, broadcast to another lane as a warning, and
//     then committed again hours later by the author of the warning.
//
// Warnings are cleared before rendering: they are an out-of-band channel and a
// caller comparing two compiles almost never wants them in the comparison. A
// caller who DOES want them should compare cfg.Warnings explicitly, which makes
// that intent visible at the call site.
//
// The walk is REFLECTIVE over exported fields rather than `json.Marshal`
// (#17249): the JSON encoder is the REST encoder, so any field tagged
// `json:"-"` — including runtime-semantic fields such as
// StaticRoute.NoInstall, SystemConfig.NTPPeers, StaticRoute.HasPreference
// and SchedulerConfig.Unresolvable — was invisible here, and any
// MarshalJSON redaction (Secret, credential URLs) masked a real difference
// behind the "<redacted>" sentinel. The reflective walk therefore:
//   - includes every exported field, `json:"-"` included, EXCEPT Config's
//     Warnings and the explicit fingerprintIgnore set below;
//   - never invokes a MarshalJSON method; all exported values (including
//     secret contents and credential URLs) enter the canonical comparison
//     stream, so no redaction sentinel can collapse distinct values;
//   - returns only a SHA-256 digest of that stream, rather than exposing the
//     canonical values in the public comparison string.
//
// The digest is an equality token, not a password-hashing interface. Do not
// log or serve it, use it for authentication, or substitute it for a password KDF.
//
// fingerprintIgnore is the COMPLETE set of documented compile-time
// diagnostics that are not semantic config content, besides Warnings.
// A field belongs here only when its type comment explicitly documents that
// equality must not validate it. TestConfigSemanticFieldsVisible pins this
// set so removing an exclusion or silently adding one fails closed.
var fingerprintIgnore = map[string]bool{
	// These diagnostics are recomputed from the config tree or duplicate
	// Warnings; their comments explicitly state that fingerprint equality
	// must not validate them.
	"Config.Diagnostics":                     true,
	"InterfacesConfig.MalformedAddresses":    true,
	"SecurityConfig.MalformedZonePairs":      true,
	"Policy.MalformedZonePairShapes":         true,
	"Policy.UnknownSecurityPoliciesChildren": true,
	"NATRule.LenientMatchDropped":            true,
	"SystemConfig.NTPTrustedKeyIDs":          true,
	"SystemSyslogConfig.TopLevelInert":       true,
	"UserspaceConfig.RetiredKnobsSeen":       true,
}

var (
	fingerprintSecretType = reflect.TypeOf(Secret{})
	fingerprintTimeType   = reflect.TypeOf(time.Time{})
)

type fingerprintPointer struct {
	typeOf reflect.Type
	ptr    uintptr
}

func ConfigFingerprint(c *Config) string {
	if c == nil {
		return "<nil>"
	}
	dup := *c
	dup.Warnings = nil
	var canonical strings.Builder
	fingerprintValue(&canonical, reflect.ValueOf(&dup), make(map[fingerprintPointer]bool))
	sum := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(sum[:])
}

// fingerprintValue appends a canonical textual rendering of v. Map keys are
// sorted, pointers are rendered structurally (with cycle detection), and JSON
// tags and MarshalJSON methods are ignored. Config's type graph uses scalar
// keys and has no unsupported channel/function/complex values.
func fingerprintValue(sb *strings.Builder, v reflect.Value, pointers map[fingerprintPointer]bool) {
	if !v.IsValid() {
		sb.WriteString("null")
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			sb.WriteString("null")
			return
		}
		key := fingerprintPointer{typeOf: v.Type(), ptr: v.Pointer()}
		if pointers[key] {
			sb.WriteString("<cycle>")
			return
		}
		pointers[key] = true
		sb.WriteByte('*')
		fingerprintValue(sb, v.Elem(), pointers)
		delete(pointers, key)
	case reflect.Interface:
		if v.IsNil() {
			sb.WriteString("null")
			return
		}
		fingerprintValue(sb, v.Elem(), pointers)
	case reflect.Struct:
		if v.Type() == fingerprintSecretType {
			secret := v.Interface().(Secret)
			sb.WriteString("Secret(")
			sb.WriteString(strconv.Quote(secret.Reveal()))
			sb.WriteByte(':')
			fingerprintValue(sb, reflect.ValueOf(secret.Junos9), pointers)
			sb.WriteByte(')')
			return
		}
		if v.Type() == fingerprintTimeType {
			sb.WriteString("time.Time(")
			sb.WriteString(strconv.Quote(v.Interface().(time.Time).Format(time.RFC3339Nano)))
			sb.WriteByte(')')
			return
		}
		t := v.Type()
		sb.WriteByte('{')
		first := true
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			if fingerprintIgnore[t.Name()+"."+f.Name] {
				continue
			}
			if !first {
				sb.WriteByte(',')
			}
			first = false
			sb.WriteString(f.Name)
			sb.WriteByte('=')
			fingerprintValue(sb, v.Field(i), pointers)
		}
		sb.WriteByte('}')
	case reflect.Map:
		if v.IsNil() {
			sb.WriteString("null")
			return
		}
		if v.Len() == 0 {
			sb.WriteString("{}")
			return
		}
		type entry struct {
			key string
			val reflect.Value
		}
		entries := make([]entry, 0, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			var kb strings.Builder
			fingerprintValue(&kb, iter.Key(), pointers)
			entries = append(entries, entry{key: kb.String(), val: iter.Value()})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
		sb.WriteByte('{')
		for i, e := range entries {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(e.key)
			sb.WriteByte(':')
			fingerprintValue(sb, e.val, pointers)
		}
		sb.WriteByte('}')
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			sb.WriteString("null")
			return
		}
		sb.WriteByte('[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				sb.WriteByte(',')
			}
			fingerprintValue(sb, v.Index(i), pointers)
		}
		sb.WriteByte(']')
	case reflect.String:
		sb.WriteString(strconv.Quote(v.String()))
	case reflect.Bool:
		sb.WriteString(strconv.FormatBool(v.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		sb.WriteString(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		sb.WriteString(strconv.FormatUint(v.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		sb.WriteString(strconv.FormatFloat(v.Float(), 'g', -1, v.Type().Bits()))
	case reflect.Complex64, reflect.Complex128:
		c := v.Complex()
		sb.WriteString(strconv.FormatFloat(real(c), 'g', -1, v.Type().Bits()/2))
		sb.WriteByte(',')
		sb.WriteString(strconv.FormatFloat(imag(c), 'g', -1, v.Type().Bits()/2))
	default:
		// No config field currently uses these kinds. Keep their type and
		// nil/presence state visible without delegating to JSON marshalling.
		sb.WriteString("<unsupported:")
		sb.WriteString(v.Type().String())
		sb.WriteByte(':')
		switch v.Kind() {
		case reflect.Chan, reflect.Func:
			if v.IsNil() {
				sb.WriteString("nil")
			} else {
				sb.WriteString("present")
			}
		case reflect.UnsafePointer:
			if v.Pointer() == 0 {
				sb.WriteString("nil")
			} else {
				sb.WriteString("present")
			}
		default:
			sb.WriteString(v.Kind().String())
		}
		sb.WriteByte('>')
	}
}

// ConfigsIdentical reports whether two compiled Configs are structurally the
// same, ignoring warnings. It exists so that the correct comparison is shorter
// to write than the incorrect one.
func ConfigsIdentical(a, b *Config) bool {
	return ConfigFingerprint(a) == ConfigFingerprint(b)
}
