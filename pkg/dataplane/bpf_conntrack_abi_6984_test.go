package dataplane

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// #6984: an EXECUTABLE pin on the C conntrack ABI's field OFFSETS.
//
// THE DEFECT THIS CATCHES, and why every pre-existing guard is blind to it.
// Three artifacts mirror `struct session_value`: Rust (`offset_of!` — a
// Rust-only transposition fails the BUILD), Go (an explicit mirror — caught by
// TestBPFSessionValueMatchesConntrackABI), and C (bpf/headers/xpf_conntrack.h —
// pinned by a COMMENT, and a comment cannot fail). Transposing
// `ingress_ifindex` and `ingress_vlan_id` in the C header alone moves the pair
// to 140/136 (v4) and 188/184 (v6) while `sizeof` stays at 144/192, because
// both fields live inside the same alignment run. MEASURED on this branch,
// with the transposition applied:
//
//	gcc/clang offsetof:  v4 ifindex=140 vlan=136 size=144  (was 136/140/144)
//	go test ./pkg/dataplane/...            -> ok, every package green
//	cargo test (whole crate, --test-threads=1) -> green
//
// Nothing in the tree compiles this header — `git grep '#include' ` finds it
// included only by its own siblings under bpf/headers/ — so `sizeof`-based
// guards are the only ones that could fire, and this mutation is chosen
// precisely to preserve `sizeof`.
//
// WHY NOT COMPILE THE HEADER WITH cc, which is the issue's first suggestion.
// It needs a C toolchain, so it needs a SKIP — and the issue names the hazard
// itself: "a guard that quietly never runs is the same as no guard". This box
// has both gcc and clang, which is exactly what makes that dangerous: the leg
// would look green here forever while never executing in a build container
// without a compiler, and nobody would learn that from a passing run. A
// Go-native guard has no skip to reason about. (The cc route was still used
// ONCE, by hand, to source the expected numbers below — see the measured
// figures in the assertions.)
//
// WHY NOT GENERATE THE CONSTANTS FROM THE HEADER (the issue's stronger
// alternative). That collapses three mirrors into one and is the better end
// state, but it changes the Go and Rust types' provenance and is a much larger
// change than the gap warrants. It also is not obviously right: the three
// mirrors are allowed to differ in trailing sync-only fields (#2360), so the
// thing to enforce is their AGREEMENT on the shared prefix, not their identity.
//
// HOW THIS AVOIDS RE-IMPLEMENTING THE COMPILER BADLY. The layout engine below
// is anchored, not trusted: the sizes it computes must equal
// ConntrackSessionValueSize / ...V6, which Go's own `unsafe.Sizeof` and Rust's
// `size_of` assert independently of this file. If the engine mis-modelled C
// alignment, the size assertion reds before the offset assertion is reached.
// `TestCStructLayoutEngineOnSyntheticStructs6984` exercises it on inputs whose
// answers do not come from this header at all.

// cStructLayout is one parsed C struct: its members in declaration order, plus
// whether it carries __attribute__((packed)).
type cStructLayout struct {
	name    string
	packed  bool
	fields  []cField
	offsets map[string]int
	size    int
	align   int
}

type cField struct {
	typ   string
	name  string
	count int // 1 for a scalar, N for `T name[N]`
}

// cScalarSizes is the size/alignment table for the scalar spellings this header
// uses. Alignment equals size for every one of them on every ABI this project
// targets (x86-64 and aarch64 LP64).
var cScalarSizes = map[string]int{
	"__u8": 1, "__s8": 1, "char": 1, "unsigned char": 1,
	"__u16": 2, "__s16": 2, "__be16": 2, "__le16": 2,
	"__u32": 4, "__s32": 4, "__be32": 4, "__le32": 4,
	"__u64": 8, "__s64": 8, "__be64": 8, "__le64": 8,
}

var (
	cCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	cLineRe    = regexp.MustCompile(`//[^\n]*`)
	cStructRe  = regexp.MustCompile(`(?m)^struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)
	cFieldRe   = regexp.MustCompile(`^((?:struct\s+)?[A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[\s*(\d+)\s*\])?$`)
)

// parseCStructs extracts every top-level `struct NAME { ... };` from src.
//
// Deliberately narrow: it understands scalars, fixed-size arrays of scalars,
// nested struct members, and __attribute__((packed)). Anything else in a member
// position is an error rather than a silent skip — a parser that quietly drops
// a member it does not understand computes a layout for a struct that does not
// exist, and would then agree with itself.
func parseCStructs(src string) (map[string]*cStructLayout, error) {
	src = cCommentRe.ReplaceAllString(src, " ")
	src = cLineRe.ReplaceAllString(src, " ")

	out := map[string]*cStructLayout{}
	for _, m := range cStructRe.FindAllStringSubmatchIndex(src, -1) {
		name := src[m[2]:m[3]]
		// Brace-match from the opening brace so a function body between two
		// struct definitions cannot be read as struct members.
		depth, end := 0, -1
		for i := m[1] - 1; i < len(src); i++ {
			switch src[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return nil, fmt.Errorf("struct %s: unterminated body", name)
		}
		body := src[m[1]:end]
		// The packed attribute belongs to THIS declaration, so look only as far
		// as the `;` that terminates it. A fixed-width lookahead window bleeds
		// into whatever follows: on a compactly written source it marked a
		// struct packed because the NEXT struct carried the attribute, and the
		// real header did not expose that because its declarations sit far
		// apart — a fixture that cannot tell correct from incorrect.
		tail := src[end:]
		if semi := strings.IndexByte(tail, ';'); semi >= 0 {
			tail = tail[:semi]
		}

		st := &cStructLayout{name: name, packed: strings.Contains(tail, "packed")}
		for _, raw := range strings.Split(body, ";") {
			decl := strings.Join(strings.Fields(raw), " ")
			if decl == "" {
				continue
			}
			fm := cFieldRe.FindStringSubmatch(decl)
			if fm == nil {
				return nil, fmt.Errorf("struct %s: unparsed member %q", name, decl)
			}
			count := 1
			if fm[3] != "" {
				n, err := strconv.Atoi(fm[3])
				if err != nil || n <= 0 {
					return nil, fmt.Errorf("struct %s: bad array length in %q", name, decl)
				}
				count = n
			}
			typ := fm[1]
			if _, scalar := cScalarSizes[typ]; !scalar && !strings.HasPrefix(typ, "struct ") {
				return nil, fmt.Errorf("struct %s: member %s has type %q, which is neither "+
					"a known scalar nor a nested struct — refusing to lay out a struct "+
					"whose members this parser does not model", name, fm[2], typ)
			}
			st.fields = append(st.fields, cField{typ: typ, name: fm[2], count: count})
		}
		out[name] = st
	}
	return out, nil
}

// layout computes offsets, size and alignment for st, resolving nested struct
// members through all. It follows the System V rule set the header targets:
// every member is placed at the next multiple of its alignment, the struct's
// alignment is the maximum of its members' (1 when packed), and the size is
// rounded up to that alignment.
func (st *cStructLayout) layout(all map[string]*cStructLayout) error {
	if st.offsets != nil {
		return nil // already computed
	}
	st.offsets = map[string]int{}
	off, maxAlign := 0, 1
	for _, f := range st.fields {
		var elemSize, elemAlign int
		if sz, ok := cScalarSizes[f.typ]; ok {
			elemSize, elemAlign = sz, sz
		} else if strings.HasPrefix(f.typ, "struct ") {
			nested, ok := all[strings.TrimPrefix(f.typ, "struct ")]
			if !ok {
				return fmt.Errorf("struct %s: member %s has unknown type %q", st.name, f.name, f.typ)
			}
			if err := nested.layout(all); err != nil {
				return err
			}
			elemSize, elemAlign = nested.size, nested.align
		} else {
			return fmt.Errorf("struct %s: member %s has unknown type %q", st.name, f.name, f.typ)
		}
		if st.packed {
			elemAlign = 1
		}
		if elemAlign > maxAlign {
			maxAlign = elemAlign
		}
		if pad := off % elemAlign; pad != 0 {
			off += elemAlign - pad
		}
		st.offsets[f.name] = off
		off += elemSize * f.count
	}
	st.align = maxAlign
	if pad := off % maxAlign; pad != 0 {
		off += maxAlign - pad
	}
	st.size = off
	return nil
}

func loadConntrackHeaderLayouts(t *testing.T) map[string]*cStructLayout {
	t.Helper()
	data, err := os.ReadFile("../../bpf/headers/xpf_conntrack.h")
	if err != nil {
		t.Fatalf("cannot read bpf/headers/xpf_conntrack.h: %v. This guard is the "+
			"ONLY executable check on the C side of the conntrack ABI; a missing "+
			"header is a failure, not a skip (#6984)", err)
	}
	structs, err := parseCStructs(string(data))
	if err != nil {
		t.Fatalf("parsing bpf/headers/xpf_conntrack.h: %v", err)
	}
	for _, want := range []string{"session_key", "session_key_v6", "session_value", "session_value_v6"} {
		st, ok := structs[want]
		if !ok {
			t.Fatalf("struct %s not found in the header — the parser matched nothing, "+
				"so every assertion below would be vacuous (#6984)", want)
		}
		if err := st.layout(structs); err != nil {
			t.Fatalf("laying out struct %s: %v", want, err)
		}
	}
	return structs
}

// TestConntrackCHeaderFieldOffsets6984 is the pin the C mirror never had.
//
// RED on revert: transpose `ingress_ifindex` and `ingress_vlan_id` in
// bpf/headers/xpf_conntrack.h — in either struct — and the offset assertions
// fail while `sizeof` stays 144/192 and every other guard in the tree stays
// green. That is the exact mutation #6984 was filed for.
func TestConntrackCHeaderFieldOffsets6984(t *testing.T) {
	structs := loadConntrackHeaderLayouts(t)

	// ANCHORS FIRST. These sizes are known independently of this file — Go's
	// unsafe.Sizeof asserts them in TestBPFSessionValueMatchesConntrackABI and
	// Rust's size_of in bpf_map_tests.rs — so if the layout engine below
	// mis-modelled C alignment, this reds before any offset is trusted.
	for _, tc := range []struct {
		name string
		want int
	}{
		{"session_key", 16},
		{"session_key_v6", 40},
		{"session_value", conntrackValueSizeV4},
		{"session_value_v6", conntrackValueSizeV6},
	} {
		if got := structs[tc.name].size; got != tc.want {
			t.Fatalf("computed sizeof(struct %s) = %d, want %d. Either the C header's "+
				"layout drifted from the Go/Rust mirrors, or this file's layout engine "+
				"is wrong — and the offsets below cannot be trusted until that is "+
				"settled (#6984)", tc.name, got, tc.want)
		}
	}

	// THE PIN. Values sourced by compiling the pristine header with BOTH gcc and
	// clang and reading offsetof; the two agreed, and they agree with the
	// derivation in the header's own comment.
	for _, tc := range []struct {
		strct, field string
		want         int
	}{
		{"session_value", "ingress_ifindex", 136},
		{"session_value", "ingress_vlan_id", 140},
		{"session_value_v6", "ingress_ifindex", 184},
		{"session_value_v6", "ingress_vlan_id", 188},
		// #9546: appended after the ingress pair, so none of the four above moved.
		{"session_value", "routing_domain", 144},
		{"session_value_v6", "routing_domain", 192},
	} {
		got, ok := structs[tc.strct].offsets[tc.field]
		if !ok {
			t.Fatalf("struct %s has no member %s — the ABI field this pin exists for "+
				"is gone or renamed (#6984)", tc.strct, tc.field)
		}
		if got != tc.want {
			t.Errorf("offsetof(struct %s, %s) = %d, want %d. The C header disagrees with "+
				"the Rust and Go mirrors about which bytes carry the session's ingress "+
				"identity: every session row's ingress interface and VLAN is mis-read, in "+
				"session display and filtering AND across HA session sync, and `sizeof` "+
				"is unchanged so no other guard in the tree fires (#6984)",
				tc.strct, tc.field, got, tc.want)
		}
	}

	// The adjacent FIB pair, same alignment run, same failure mode. Included
	// because a transposition guard that names only the two fields the issue
	// happened to notice invites the next one to land two fields over.
	for _, tc := range []struct {
		field string
		want  int
	}{
		{"fib_ifindex", 116},
		{"fib_vlan_id", 120},
		{"fib_gen", 134},
	} {
		if got := structs["session_value"].offsets[tc.field]; got != tc.want {
			t.Errorf("offsetof(struct session_value, %s) = %d, want %d (#6984)",
				tc.field, got, tc.want)
		}
	}
}

// TestCStructLayoutEngineOnSyntheticStructs6984 exercises the layout engine on
// inputs whose expected answers come from neither the conntrack header nor the
// constants this package already ships — so a bug in the engine cannot hide
// behind the anchors above.
//
// Each case was verified against gcc AND clang before being written down.
func TestCStructLayoutEngineOnSyntheticStructs6984(t *testing.T) {
	const src = `
struct probe_pad {
	__u8  a;
	__u32 b;
	__u8  c;
};
struct probe_packed {
	__u8  a;
	__u32 b;
	__u8  c;
} __attribute__((packed));
struct probe_array {
	__u16 a;
	__u8  b[6];
	__u64 c;
};
struct probe_nested {
	__u8  a;
	struct probe_packed inner;
	__u8  z;
};
`
	structs, err := parseCStructs(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, st := range structs {
		if err := st.layout(structs); err != nil {
			t.Fatalf("layout %s: %v", st.name, err)
		}
	}
	for _, tc := range []struct {
		strct, field string
		off          int
	}{
		// a@0, pad 1..4, b@4, c@8, tail pad to 12.
		{"probe_pad", "a", 0}, {"probe_pad", "b", 4}, {"probe_pad", "c", 8},
		// packed: no padding anywhere.
		{"probe_packed", "a", 0}, {"probe_packed", "b", 1}, {"probe_packed", "c", 5},
		// a@0, b[6]@2 (u8 array, align 1), c needs 8 -> 8.
		{"probe_array", "a", 0}, {"probe_array", "b", 2}, {"probe_array", "c", 8},
		// a packed member has align 1, so inner sits at 1 and z right after it.
		{"probe_nested", "a", 0}, {"probe_nested", "inner", 1}, {"probe_nested", "z", 7},
	} {
		if got := structs[tc.strct].offsets[tc.field]; got != tc.off {
			t.Errorf("offsetof(%s, %s) = %d, want %d", tc.strct, tc.field, got, tc.off)
		}
	}
	for _, tc := range []struct {
		strct string
		size  int
	}{
		{"probe_pad", 12}, {"probe_packed", 6}, {"probe_array", 16}, {"probe_nested", 8},
	} {
		if got := structs[tc.strct].size; got != tc.size {
			t.Errorf("sizeof(%s) = %d, want %d", tc.strct, got, tc.size)
		}
	}

	// The parser must REFUSE a member it does not understand rather than drop
	// it: a silently skipped member yields a layout for a struct that does not
	// exist, and the engine would then agree with itself.
	if _, err := parseCStructs("struct bad {\n\tfloat x;\n};\n"); err == nil {
		t.Error("parseCStructs accepted a member type it cannot lay out; an unparsed " +
			"member must be an error, never a silent skip (#6984)")
	}
}
