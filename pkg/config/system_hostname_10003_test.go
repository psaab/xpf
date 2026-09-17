package config_test

// #10003 — `system host-name` was a scalar leaf with no valueType/validator
// while its siblings carry them, and the compiler read it (both spellings)
// with no charset/length check. Spaced/overlong/malformed names committed
// clean and reached sethostname(2) + /etc/hostname verbatim.
//
// Enforcement is split by spelling, and the cells below pin the split:
//   - block/set spelling (`set system host-name X`, `system { host-name X; }`)
//     is owned by the schema gate (ValidateSystemHostname on the typed leaf):
//     strict commit-check/commit rejects, the tolerant Load/SyncApply ingress
//     downgrades to a warning via the generic #1319 machinery.
//   - brace-elided hierarchical spelling (`system host-name X;`) packs onto
//     the `system` container's Keys, which the gate ignores by design (no
//     packedTail opt-in, per the #6956 narrowing), so the compiler validates
//     it at the #6956 read: strict CompileConfig rejects, CompileConfigLenient
//     warns (opts.lenientSystemHostname, #1960 no-brick).
//
// FAIL-ON-REVERT: neutering ValidateSystemHostname (return nil) flips every
// reject cell; detaching the validator from the leaf flips the gate cells;
// dropping the compiler packed-read check flips the elided CompileConfig
// cells; dropping the lenient flag flips the lenient warn cell back to a
// brick (or to silence, if the check is dropped instead).

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// hostName10003SetCmd quotes the value so characters the lexer would
// otherwise reject in a bare token (space, '!', etc.) reach the typed-leaf
// validator intact — exactly how an operator must type such a name.
func hostName10003SetCmd(host string) string {
	return "set system host-name " + quote10003(host)
}

func quote10003(s string) string {
	// %q matches operator quoting for every value in these tables (no
	// backslashes or double quotes appear in them).
	return "\"" + s + "\""
}

// The invalid population: spaced, overlong (label, kernel total, DNS total),
// bad charset, plus the structural edges (empty label, leading/trailing
// hyphen). Every strict cell below must reject each of these; every tolerant
// cell must warn-and-continue.
func invalidHostNames10003() []string {
	return []string{
		"bad name",              // spaced
		"bad!name",              // bad charset
		"under_score",           // underscore is non-LDH (RFC 1035)
		"münchen",               // non-ASCII (IDN source chars are non-LDH)
		"-leading.example.net",  // leading hyphen
		"trailing-.example.net", // trailing hyphen
		"doubled..dots.example", // empty label
		".leading.example",      // empty label
		".",                     // no labels
		strings.Repeat("a", 64), // label over 63 octets
		strings.Repeat("a", 32) + "." + strings.Repeat("b", 32),       // 65-byte kernel name
		strings.Repeat("a", 31) + "." + strings.Repeat("b", 32) + ".", // 65 bytes incl. trailing dot
		strings.Repeat("b", 300),                                      // total over 253 octets
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + "." +
			strings.Repeat("e", 63) + "." + strings.Repeat("f", 63) + ".g", // 4x63+dots > 253, every label legal
	}
}

func validHostNames10003() []string {
	return []string{
		"fw1",
		"core-sw1",
		"router1.example.net",
		"WAN.Example.NET",  // DNS is case-insensitive; upper-case is benign
		"fw1.example.net.", // single trailing dot (absolute-name canonical form)
		"a",
		strings.Repeat("a", 63), // label at the 63-octet cap
		// Linux HOST_NAME_MAX boundary: 32+1+31 = 64 bytes.
		strings.Repeat("a", 32) + "." + strings.Repeat("b", 31),
		// The trailing dot counts toward the syscall length: 31+1+31+1 = 64.
		strings.Repeat("a", 31) + "." + strings.Repeat("b", 31) + ".",
	}
}

func TestValidateSystemHostname_10003(t *testing.T) {
	for _, h := range validHostNames10003() {
		if err := config.ValidateSystemHostname(h, nil); err != nil {
			t.Errorf("accept %q: unexpected error: %v", h, err)
		}
	}
	// Empty is unset, not invalid: the compiler skips it and applyHostname
	// early-returns. Rejecting "" here would brick tolerant loads of a
	// config that simply names no host-name.
	if err := config.ValidateSystemHostname("", nil); err != nil {
		t.Errorf("accept %q: empty must stay valid (unset leaf): %v", "", err)
	}
	for _, h := range invalidHostNames10003() {
		if err := config.ValidateSystemHostname(h, nil); err == nil {
			t.Errorf("reject %q: expected an error, got nil", h)
			continue
		} else if !strings.Contains(err.Error(), "host-name") {
			t.Errorf("reject %q: error must name the leaf: %v", h, err)
		}
	}
}

func TestSchemaValidate_SystemHostname_10003(t *testing.T) {
	// Set spelling (nested AST): the gate owns it.
	for _, h := range validHostNames10003() {
		if err := flatSchemaCheck(t, hostName10003SetCmd(h)); err != nil {
			t.Errorf("set accept %q: unexpected commit error: %v", h, err)
		}
	}
	for _, h := range invalidHostNames10003() {
		err := flatSchemaCheck(t, hostName10003SetCmd(h))
		if err == nil {
			t.Errorf("set reject %q: expected a commit error, got nil", h)
			continue
		}
		if !strings.Contains(err.Error(), "host-name") {
			t.Errorf("set reject %q: error must name the leaf: %v", h, err)
		}
	}

	// Block spelling (hierarchical AST): the gate owns it too.
	block := func(h string) string {
		return "system { host-name " + quote10003(h) + "; }"
	}
	if err := schemaCheck(t, block("router1.example.net")); err != nil {
		t.Errorf("block accept: unexpected commit error: %v", err)
	}
	for _, h := range []string{"bad name", strings.Repeat("a", 300), "bad!name", "bad..name"} {
		if err := schemaCheck(t, block(h)); err == nil {
			t.Errorf("block reject %q: expected a commit error, got nil", h)
		} else if !strings.Contains(err.Error(), "host-name") {
			t.Errorf("block reject %q: error must name the leaf: %v", h, err)
		}
	}
}

// The brace-elided spelling packs onto the `system` container's Keys, and
// the gate ignores container packed tails without a packedTail opt-in —
// deliberately not opted in (see the #6956 narrowing in compileSystem).
// This cell pins that the GATE stays silent here so a future admission (or
// a packedTail widening) shows up as a deliberate diff, not a silent
// behavior change; the COMPILER owns this spelling (next test).
func TestSchemaValidate_SystemHostnameElidedStaysSilent_10003(t *testing.T) {
	p := config.NewParser("system host-name \"bad name\";")
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("gate must stay silent on the elided spelling (compiler jurisdiction): %v", err)
	}
}

// Strict compiler jurisdiction: the elided spelling, invisible to the gate,
// must still be rejected at strict commit. Uses hierarchical text so the
// value arrives on the system node's Keys exactly as #6956 describes.
func TestCompileConfig_SystemHostnameElided_10003(t *testing.T) {
	compile := func(text string) error {
		p := config.NewParser(text)
		tree, perrs := p.Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse errors for %q: %v", text, perrs)
		}
		_, err := config.CompileConfig(tree)
		return err
	}
	if err := compile("system host-name fw1;"); err != nil {
		t.Errorf("elided accept: unexpected compile error: %v", err)
	}
	if err := compile("system host-name router1.example.net;"); err != nil {
		t.Errorf("elided FQDN accept: unexpected compile error: %v", err)
	}
	for _, h := range []string{
		"bad name",
		strings.Repeat("a", 300),
		"bad!name",
		"bad..name",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a", 32) + "." + strings.Repeat("b", 32),
		strings.Repeat("a", 31) + "." + strings.Repeat("b", 32) + ".",
	} {
		err := compile("system host-name " + quote10003(h) + ";")
		if err == nil {
			t.Errorf("elided reject %q: expected a strict compile error, got nil", h)
			continue
		}
		if !strings.Contains(err.Error(), "host-name") {
			t.Errorf("elided reject %q: error must name the leaf: %v", h, err)
		}
	}
}

// Tolerant compiler jurisdiction (#1960 no-brick): the elided spelling must
// warn-and-continue, never brick the load. The block spelling is the gate's
// jurisdiction — the compiler stays silent on it (the Load path already
// warns via the generic #1319 downgrade), so a compiler-side double warning
// would show up here.
func TestCompileConfigLenient_SystemHostname_10003(t *testing.T) {
	compileLenient := func(text string) (*config.Config, error) {
		p := config.NewParser(text)
		tree, perrs := p.Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse errors for %q: %v", text, perrs)
		}
		return config.CompileConfigLenient(tree)
	}
	// Elided invalid: must boot with a warning naming the leaf.
	cfg, err := compileLenient("system host-name \"bad name\";")
	if err != nil {
		t.Fatalf("lenient elided must not brick: %v", err)
	}
	if cfg == nil {
		t.Fatal("lenient elided returned a nil config")
	}
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, "host-name") {
		t.Errorf("lenient elided must warn naming host-name; warnings = %v", cfg.Warnings)
	}
	// The value remains available to the tolerant runtime unchanged; the
	// warning is the migration signal and the next strict commit rejects it.
	if cfg.System.HostName != "bad name" {
		t.Errorf("lenient elided must compile the value verbatim, got %q", cfg.System.HostName)
	}

	// The DNS-valid but Linux-overlong compact value must take the same
	// tolerant warning path as the other malformed values.
	kernelOverlong := strings.Repeat("a", 32) + "." + strings.Repeat("b", 32)
	cfg, err = compileLenient("system host-name " + quote10003(kernelOverlong) + ";")
	if err != nil {
		t.Fatalf("lenient kernel-overlong elided must not brick: %v", err)
	}
	if cfg == nil || cfg.System.HostName != kernelOverlong {
		t.Fatalf("lenient kernel-overlong value changed: cfg=%+v", cfg)
	}
	if joined := strings.Join(cfg.Warnings, "\n"); !strings.Contains(joined, "host-name") {
		t.Errorf("lenient kernel-overlong must warn naming host-name; warnings = %v", cfg.Warnings)
	}

	kernelOverlongDot := strings.Repeat("a", 31) + "." + strings.Repeat("b", 32) + "."
	cfg, err = compileLenient("system host-name " + quote10003(kernelOverlongDot) + ";")
	if err != nil {
		t.Fatalf("lenient trailing-dot kernel-overlong must not brick: %v", err)
	}
	if cfg == nil || cfg.System.HostName != kernelOverlongDot {
		t.Fatalf("lenient trailing-dot value changed: cfg=%+v", cfg)
	}
	if joined := strings.Join(cfg.Warnings, "\n"); !strings.Contains(joined, "host-name") {
		t.Errorf("lenient trailing-dot kernel-overlong must warn naming host-name; warnings = %v", cfg.Warnings)
	}
	// Block invalid: the compiler stays silent (gate jurisdiction).
	cfg, err = compileLenient("system { host-name \"bad name\"; }")
	if err != nil {
		t.Fatalf("lenient block must not brick: %v", err)
	}
	if cfg == nil {
		t.Fatal("lenient block returned a nil config")
	}
	if joined := strings.Join(cfg.Warnings, "\n"); strings.Contains(joined, "host-name") {
		t.Errorf("lenient block must not warn from the compiler (gate owns it); warnings = %v", cfg.Warnings)
	}
}
