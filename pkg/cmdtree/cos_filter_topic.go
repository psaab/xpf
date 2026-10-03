package cmdtree

// #6858: the `name <n>` / `type <t>` filter grammar shared by `show
// class-of-service classifier` and `show class-of-service rewrite-rule`, and
// the ShowText topic encoding the REMOTE `cli` binary uses to carry those
// filters to the gRPC server.
//
// This lives in cmdtree because the tokens it consumes are the tokens the
// operational tree offers: the `name` / `type` completion children in tree.go
// and the parser here are two halves of one grammar, and the package is
// already the SSOT for "the same command means the same thing on the local
// CLI, the remote CLI, and gRPC".
//
// Before #6858 the grammar existed THREE times — pkg/cli parsed args into
// filters, cmd/cli parsed the same args into a topic, and pkg/grpcapi decoded
// the topic — with a comment asking future editors to keep the first two "in
// step". They had already drifted (pkg/cli honored a trailing `name` keyword
// over a leading bare token; cmd/cli did not), and the topic encoding could not
// carry a filter value containing the `,` it used as its own separator, so
// `show class-of-service rewrite-rule "rw,x"` rendered a DIFFERENT rule on the
// remote binary than on the local one. Both surfaces now call the same three
// functions, so a divergence is not a bug to be caught by a mirrored test
// table — it is unrepresentable.

import (
	"fmt"
	"strings"
)

// CoSNameTypeArgsUsage is the canonical usage string for the `name <n>` /
// `type <t>` filter grammar, shared by the local CLI and the remote `cli`
// binary so a parse error reads identically on both (#11834).
const CoSNameTypeArgsUsage = "usage: show class-of-service classifier|rewrite-rule " +
	"[<name>] [name <name>] [type <type>]"

// ParseCoSNameTypeArgs extracts the optional `name <n>` / `type <t>` filters
// from the tokens following `show class-of-service classifier|rewrite-rule`.
//
// A LEADING BARE TOKEN is accepted as the name, i.e. `show class-of-service
// rewrite-rule rw-dscp` == `... rewrite-rule name rw-dscp`. Both commands'
// cmdtree nodes carry a DynamicFn offering rule names directly under the
// command (tree.go), so an operator who tab-completes a name and presses enter
// submits exactly that bare form. Before #6848 the keyword-only parser silently
// ignored it and dumped every rule — completion promised a filter the parser
// did not implement.
//
// A later explicit `name` keyword wins over the bare positional: the operator
// typed the keyword form deliberately.
//
// Parsing fails CLOSED (#11834): an unknown token or a filter keyword with no
// value is an error, not a silently-ignored token that falls through to a
// broader dump. A typo (`show class-of-service classifier type dscp tyep`) or
// a bare trailing keyword (`show class-of-service classifier name`) used to
// render every classifier; silently widening a scoped query is worse than
// it. This mirrors the strict #3347 `show security log` parser.
func ParseCoSNameTypeArgs(args []string) (nameFilter, typeFilter string, err error) {
	if len(args) > 0 && args[0] != "name" && args[0] != "type" {
		nameFilter = args[0]
		args = args[1:]
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "name":
			if i+1 >= len(args) || args[i+1] == "name" || args[i+1] == "type" {
				return "", "", fmt.Errorf("missing value for %q\n%s", "name", CoSNameTypeArgsUsage)
			}
			nameFilter = args[i+1]
			i++
		case "type":
			if i+1 >= len(args) || args[i+1] == "name" || args[i+1] == "type" {
				return "", "", fmt.Errorf("missing value for %q\n%s", "type", CoSNameTypeArgsUsage)
			}
			typeFilter = args[i+1]
			i++
		default:
			return "", "", fmt.Errorf("unknown argument %q\n%s", args[i], CoSNameTypeArgsUsage)
		}
	}
	return nameFilter, typeFilter, nil
}

// CoSNameTypeTopic encodes the filters as a gRPC ShowText topic of the form
// "<prefix>[:name=<n>][,type=<t>]". Params are emitted in a canonical order
// (name, then type) regardless of the order the operator typed them, so one
// set of filters has one encoding.
//
// Values are escaped by escapeCoSTopicValue; ParseCoSNameTypeTopic is its
// inverse. An empty filter is omitted rather than encoded as an empty value,
// matching the renderers, which treat "" as "no filter".
func CoSNameTypeTopic(prefix, nameFilter, typeFilter string) string {
	var params []string
	if nameFilter != "" {
		params = append(params, "name="+escapeCoSTopicValue(nameFilter))
	}
	if typeFilter != "" {
		params = append(params, "type="+escapeCoSTopicValue(typeFilter))
	}
	if len(params) == 0 {
		return prefix
	}
	return prefix + ":" + strings.Join(params, ",")
}

// ParseCoSNameTypeTopic extracts the `name=` / `type=` params from a
// "<prefix>[:k=v,k=v]" ShowText topic. It is the inverse of CoSNameTypeTopic.
func ParseCoSNameTypeTopic(topic, prefix string) (nameFilter, typeFilter string) {
	params := strings.TrimPrefix(topic, prefix)
	params = strings.TrimPrefix(params, ":")
	for _, kv := range strings.Split(params, ",") {
		// Tolerate whitespace around a hand-written topic's params. Encoded
		// values never rely on this: escapeCoSTopicValue escapes spaces, so a
		// filter value's own leading/trailing space survives the trim.
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "name":
			nameFilter = unescapeCoSTopicValue(v)
		case "type":
			typeFilter = unescapeCoSTopicValue(v)
		}
	}
	return nameFilter, typeFilter
}

const topicHexDigits = "0123456789ABCDEF"

// escapeCoSTopicValue percent-escapes the bytes that carry STRUCTURE in a
// ShowText topic, so a filter value containing one survives the round trip.
//
// A rewrite-rule name is operator-chosen and the config store accepts a quoted
// name containing any of these (verified against the real commit path: `set
// class-of-service rewrite-rules dscp "rw,x"` commits and reads back as
// `rw,x`). Unescaped, the `,` split the params and the name truncated at the
// comma, so the remote surface rendered a different rule — or, where the
// truncated prefix named nothing, told the operator their rule did not exist.
//
// A value with none of these bytes is returned unchanged, so the common topic
// is byte-identical to the pre-#6858 encoding. Mixed-version note: a NEW `cli`
// talking to an OLD xpfd sends `%2C` for a comma-bearing name, which the old
// decoder does not unescape, so it reports no match instead of silently
// rendering the wrong rule — visibly wrong rather than confidently wrong. The
// two ship together (scripts/image/bake.py, make test-deploy).
func escapeCoSTopicValue(v string) string {
	if strings.IndexAny(v, "%,=: ") < 0 {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 8)
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '%', ',', '=', ':', ' ':
			b.WriteByte('%')
			b.WriteByte(topicHexDigits[c>>4])
			b.WriteByte(topicHexDigits[c&0x0f])
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// unescapeCoSTopicValue reverses escapeCoSTopicValue.
//
// It is deliberately TOLERANT: a `%` not followed by two hex digits is left
// literal rather than treated as a malformed escape. That keeps a topic written
// by hand — or by an older `cli` that never escaped anything — decoding to the
// same value it did before, since a rule name may itself contain a bare `%`.
func unescapeCoSTopicValue(v string) string {
	if !strings.Contains(v, "%") {
		return v
	}
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		if v[i] == '%' && i+2 < len(v) {
			if hi, ok := unhexTopicDigit(v[i+1]); ok {
				if lo, ok := unhexTopicDigit(v[i+2]); ok {
					b.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

func unhexTopicDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
