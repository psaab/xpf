#!/bin/sh
# scripts/go-buildtag-census.sh — census over Go build-tagged test files (#9922 F-159).
#
# WHAT IT ASSERTS
#
#   Every `*_test.go` carrying a `//go:build` constraint gets a COMPILE leg:
#   for single-identifier constraints (the `functional1944` shape),
#   `go vet -tags <ident> <pkgdir>` must pass. `go vet` never executes the
#   package, so the leg is safe against TestMain side effects.
#
# WHY IT EXISTS
#
#   A build-tagged test file is INVISIBLE to the default gate: `go test ./...`
#   and `go vet ./...` both silently exclude it, and the summary line for
#   "everything passed" and "this file never compiled" is byte-identical.
#   `pkg/daemon/login_password_functional_test.go` (tag `functional1944`) can
#   rot — fail to compile, drift from the API it exercises — for any number
#   of releases while every gate stays green. This is the #7296 shape one
#   layer down: a subject that NOTHING runs, with no census noticing.
#
# WHAT COUNTS AS A CONSTRAINT
#
#   A `^//go:build` line BEFORE the first `^package ` line. A `//go:build`
#   line after the package clause is ignored by the go tool too (it is a
#   comment, a fixture literal, or prose), so the census ignores it the same
#   way rather than crying wolf over canary tests that merely MENTION tags.
#
# FALSIFIABILITY — what this reports when the property is FALSE
#
#   * A tagged file that no longer COMPILES under its tag fails the census:
#     the `go vet -tags` leg exits nonzero and the census exits 1 naming the
#     file, the tag, and the vet diagnostic.
#   * A NEW tagged file is picked up by discovery on the first run after it
#     lands — no registration step, so there is nothing to forget.
#   * A COMPLEX constraint (`//go:build foo && bar`, `!cgo`, ...) is printed
#     as a NEEDS-REVIEW line: loud, non-failing. The census has no compile
#     leg for it and says so instead of silently dropping it (none exist
#     today; the first one must be impossible to miss, not impossible to land).
#   * If discovery finds NOTHING while the known tagged file is still on disk,
#     the census FAILS closed. A parse that cannot see `functional1944` is
#     broken, not clean — an inverted matcher plus an empty board is the exact
#     failure this cohort exists to prevent.
#   * Without `go` the census SKIPs (exit 77, the hermetic-runner convention):
#     "the measurement did not happen" is reported as a skip, never as green.
#
# WHAT IT DELIBERATELY DOES NOT DO
#
#   It does not RUN tagged tests (some need root, a container, hardware). It
#   compiles them. A file that compiles but fails at runtime is a matter for
#   the gate that runs it, not for this census.
#
#   No overlap with #9812 (scripts/go-skip-census.sh): that census counts
#   `t.Skip` call sites, not build tags — it has no `go:build` handling.
#
# USAGE
#   sh scripts/go-buildtag-census.sh          # census this tree
GO=${GO:-go}

# The tool check comes before everything else — even the path computation
# below, which needs `dirname`. Without go there is no compile leg, so there
# is no measurement: a skip, never a green board. `command` is a shell
# builtin, so this branch survives even an empty PATH (the self-test's
# no-go cell proves it).
if ! command -v "$GO" >/dev/null 2>&1; then
	echo "go-buildtag census: SKIP (go not found: '$GO')"
	exit 77
fi

# shellcheck disable=SC1007
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1007
DEFAULT_ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)

# ── parameters (env-overridable so the self-test can drive a fixture tree) ──
ROOT=${GO_BUILDTAG_ROOT:-$DEFAULT_ROOT}
SCAN_DIRS=${GO_BUILDTAG_DIRS:-"pkg cmd test"}
KNOWN=${GO_BUILDTAG_KNOWN:-"pkg/daemon/login_password_functional_test.go"}

cd "$ROOT" || { echo "FATAL: cannot cd to $ROOT" >&2; exit 2; }

FAIL=0
note_fail() { echo "  FAIL: $*" >&2; FAIL=$((FAIL + 1)); }
note_pass() { echo "  PASS: $*"; }

# ── 1. discover: *_test.go with a ^//go:build line before the ^package line ──
existing_dirs=""
for d in $SCAN_DIRS; do
	[ -d "$d" ] && existing_dirs="$existing_dirs $d"
done

# One awk over every candidate: FNR==1 resets per file, so each file's head
# (everything before its first ^package line) is scanned independently.
# Emits "path<TAB>constraint" per pre-package //go:build line.
discovered=""
if [ -n "$existing_dirs" ]; then
	# shellcheck disable=SC2086
	discovered=$(find $existing_dirs -name '*_test.go' -exec awk '
		FNR == 1 { in_head = 1 }
		in_head && /^package / { in_head = 0 }
		in_head && /^\/\/go:build / {
			expr = $0
			sub(/^\/\/go:build[ \t]+/, "", expr)
			print FILENAME "\t" expr
		}
	' {} + 2>/dev/null | sed 's|^\./||')
fi

n_tagged=0
if [ -n "$discovered" ]; then
	n_tagged=$(printf '%s\n' "$discovered" | grep -c . || true)
fi

echo "go-buildtag census: $n_tagged tagged test file(s)"
if [ -n "$discovered" ]; then
	printf '%s\n' "$discovered" | while IFS='	' read -r file expr; do
		echo "  $file: //go:build $expr"
	done
fi

# ── 2. fail closed: the known tagged file must be VISIBLE, not merely present ──
# If it exists on disk but discovery missed it — an inverted matcher, a moved
# glob, a parse that finds nothing — the board is broken, not clean.
if [ -f "$KNOWN" ]; then
	# Newline-padded exact match: anchored at line start by the newline,
	# terminated by the TAB separator, so no regex and no prefix confusion.
	case "
$discovered
" in
	*"
$KNOWN	"*)
			note_pass "fail-closed control: $KNOWN is discovered"
			;;
		*)
			note_fail "fail-closed: known tagged file $KNOWN exists but was NOT discovered (the parse is broken, not clean)"
			;;
	esac
fi

# ── 3. compile legs: one `go vet -tags` per (identifier, pkgdir) ──
# Single-identifier constraints only. Anything else (negation, &&/||,
# parens) is a NEEDS-REVIEW line: loud, non-failing — the census must not
# silently drop a shape it cannot compile-check.
n_vet=0
n_review=0
vetted=""
# POSIX-sh note: the row loop below iterates the newline list with IFS
# splitting, not a `while read` pipeline, because POSIX sh has no lastpipe
# and a pipeline loop would run in a subshell where FAIL/n_vet/n_review
# updates are lost. Filenames with newlines would split here; Go test files
# never carry them, and temp files per row would be worse than the caveat.
OLD_IFS=$IFS
IFS='
'
# shellcheck disable=SC2162
for row in $discovered; do
	IFS=$OLD_IFS
	[ -n "$row" ] || { IFS='
'; continue; }
	file=${row%%	*}
	expr=${row#*	}
	case "$expr" in
		''|*[!A-Za-z0-9_.]*)
			echo "  NEEDS-REVIEW: $file carries a complex constraint ('$expr') — no compile leg covers it"
			n_review=$((n_review + 1))
			;;
		*)
			pkgdir=$(dirname -- "$file")
			key="$expr@$pkgdir"
			case " $vetted " in
				*" $key "*)
					;;
				*)
					vetted="$vetted $key"
					if vet_out=$("$GO" vet -tags "$expr" "./$pkgdir" 2>&1); then
						note_pass "vet -tags $expr ./$pkgdir ($file compiles)"
						n_vet=$((n_vet + 1))
					else
						note_fail "vet -tags $expr ./$pkgdir failed ($file does not compile under its tag)"
						printf '%s\n' "$vet_out" | sed 's/^/         /' >&2
					fi
					;;
			esac
			;;
	esac
	IFS='
'
done
IFS=$OLD_IFS

# ── 4. verdict ──
echo ""
echo "go-buildtag census: $n_tagged tagged file(s), $n_vet vet leg(s) OK, $n_review needs-review"
if [ "$FAIL" -ne 0 ]; then
	echo "go-buildtag census: FAIL" >&2
	exit 1
fi
echo "go-buildtag census: OK"
exit 0
