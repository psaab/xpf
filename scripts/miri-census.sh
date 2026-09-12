#!/bin/sh
# scripts/miri-census.sh -- census over the MIRI COVERAGE CLAIMS in userspace-dp
# (#9499 member 2).
#
# WHAT IT ASSERTS
#
#   Every file under userspace-dp/ that mentions Miri -- a `cfg(miri)` gate, a
#   `cfg(not(miri))` exclusion, or a prose claim that something "runs under
#   miri" / "keeps miri coverage" -- is either COVERED by a module registered
#   in userspace-dp/MIRI.registry (which `make test-miri` actually executes),
#   or DECLARED with a one-line reason in userspace-dp/MIRI.unregistered.
#
# WHY IT EXISTS
#
#   #9499's finding was not that Miri found something. It was that FOUR
#   separate in-tree comments asserted Miri coverage -- "the deterministic
#   example tests keep miri coverage of the same fns", "these also run under
#   miri", "miri-coverable twin" -- while NO make target ran Miri at all. The
#   sentences were not false about the code's shape; they were false about the
#   world, and a reader takes them as a protection that exists. That is the
#   #7296/#8302 census shape applied to a claim rather than to a file.
#
#   A registry alone does not fix it, because a registry can shrink. Deleting
#   the last line of MIRI.registry makes `make test-miri` quieter, not louder.
#   This census is what turns that deletion into a failure: the claims the
#   deleted module was covering become undeclared, and the census exits 1.
#
# FALSIFIABILITY -- what this reports when the property is FALSE
#
#   * A registry line deleted (the subset silently shrinking, the failure the
#     issue names): every claim file that line covered is printed under
#     "UNCOVERED and undeclared" and the census exits 1.
#   * A NEW file that mentions Miri, added with no registry entry and no
#     declaration: reported the same way on the first run after it lands.
#   * A declared file that BECOMES covered: also a FAIL ("remove it from
#     MIRI.unregistered"). The declared list may only shrink, so it cannot be
#     used to re-hide a module later.
#   * A registry entry naming a module that does not resolve to a real path:
#     FAIL. A registry pointing at a deleted module is a green face on the
#     exact shrink this exists to catch.
#   * A registry entry whose floor is not a positive integer: FAIL. `0 passed`
#     must not be expressible as a passing floor -- see `make test-miri`.
#   * An EMPTY registry: FAIL. A census that sweeps an empty set and reports a
#     clean board is the failure mode #7296 guards against.
#   * If the claim matcher breaks so that NOTHING is ever discovered, the
#     discovery count is zero and the census FAILS. Separately the POSITIVE
#     CONTROL trips by name: userspace-dp/src/afxdp/types/cos.rs carries Miri
#     claims and is covered by a registered module, so it must classify
#     COVERED -- and it may never appear in the declared list. Without the
#     control, a broken matcher plus a regenerated declaration file is a green
#     census over an inverted world.
#
#   It is hermetic: a pure file scan. No cargo, no Miri, no network, no build.
#   "The measurement did not happen" is not a state it can be in; it either
#   scans the tree or fails to start. Runs in well under a second.
#
# WHAT COUNTS AS A CLAIM
#
#   The literal token `miri`, case-insensitive, anywhere in a tracked file
#   under userspace-dp/src/ or in a userspace-dp README.md. Deliberately a
#   plain token match and not a semantic one: a matcher that tried to tell a
#   "real" claim from an incidental mention would be the component most likely
#   to break silently, and its breakage would look like a clean board.
set -u

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT" || exit 1

REGISTRY=userspace-dp/MIRI.registry
UNREG=userspace-dp/MIRI.unregistered
CONTROL=userspace-dp/src/afxdp/types/cos.rs

FAIL=0
note_fail() {
	FAIL=$((FAIL + 1))
	echo "" >&2
	echo "  FAIL: $*" >&2
}

[ -f "$REGISTRY" ] || { echo "miri census: missing $REGISTRY" >&2; exit 1; }
[ -f "$UNREG" ] || { echo "miri census: missing $UNREG" >&2; exit 1; }

strip_comments() { grep -v '^[[:space:]]*#' "$1" | grep -v '^[[:space:]]*$'; }

# ---------------------------------------------------------------- registry ---
# Resolve each registered module path to the file or directory it names, and
# collect the set of paths it COVERS.
covered_paths=""
n_registered=0
while IFS= read -r line; do
	mod=$(printf '%s\n' "$line" | awk '{print $1}')
	[ -n "$mod" ] || continue
	floor=$(printf '%s\n' "$line" | awk '{print $2}')
	# Field-based, not `cut -d' '`: the columns are separated by RUNS of
	# spaces, so `cut -f3-` on a two-space gap returns the FLOOR as the
	# reason and a reason-less entry escapes the check below.
	reason=$(printf '%s\n' "$line" | awk '{$1="";$2="";print}' | sed 's/^[[:space:]]*//')
	n_registered=$((n_registered + 1))

	case "$floor" in
	'' | *[!0-9]*)
		note_fail "registry floor for '$mod' is not an integer: '$floor'"
		continue
		;;
	esac
	[ "$floor" -gt 0 ] 2>/dev/null || note_fail "registry floor for '$mod' is not positive: '$floor' -- a floor of 0 would let a leg that ran nothing pass"
	[ -n "$reason" ] || note_fail "registry entry '$mod' has no reason; the reason is what makes the Miri budget a decision instead of an accident"

	rel=$(printf '%s\n' "$mod" | sed 's/::*$//; s|::|/|g')
	base="userspace-dp/src/$rel"
	if [ -f "$base.rs" ] || [ -d "$base" ]; then
		# BOTH shapes, not either: a module can be `foo.rs` beside a `foo/`
		# directory, and `cargo miri test -- foo::` runs the tests in both.
		# Covering only the first one found would leave the other's claims
		# reported as undeclared while the leg was in fact running them.
		[ -f "$base.rs" ] && covered_paths="$covered_paths
$base.rs"
		[ -d "$base" ] && covered_paths="$covered_paths
$(find "$base" -type f 2>/dev/null)"
	else
		note_fail "registered module '$mod' resolves to no file: neither $base.rs nor $base/ exists"
		{
			echo "        A registry entry pointing at a module that no longer exists is the"
			echo "        silent-shrink failure wearing a green face: \`make test-miri\` would"
			echo "        filter on a name that matches nothing and report a clean run."
		} >&2
	fi
done <<EOF
$(strip_comments "$REGISTRY")
EOF

if [ "$n_registered" -eq 0 ]; then
	note_fail "$REGISTRY registers NO modules"
	{
		echo "        An empty registry makes \`make test-miri\` a target that runs Miri over"
		echo "        nothing and exits 0. That is the shape this census exists to refuse."
	} >&2
fi

covered_paths=$(printf '%s\n' "$covered_paths" | grep . | sort -u)

# ------------------------------------------------------------- declarations ---
declared_paths=""
n_declared=0
while IFS= read -r line; do
	p=$(printf '%s\n' "$line" | awk '{print $1}')
	[ -n "$p" ] || continue
	reason=$(printf '%s\n' "$line" | awk '{$1="";print}' | sed 's/^[[:space:]]*//')
	n_declared=$((n_declared + 1))
	declared_paths="$declared_paths
$p"
	[ -n "$reason" ] || note_fail "declaration for '$p' has no reason"
	[ -e "$p" ] || note_fail "declared path does not exist in the tree: $p"
	if printf '%s\n' "$covered_paths" | grep -qxF "$p"; then
		note_fail "declared-unregistered path IS covered by a registered module: $p"
		{
			echo "        Remedy: remove it from $UNREG."
			echo "        This list may only SHRINK. Leaving a covered path declared lets the"
			echo "        declaration be reused to re-hide the module after it is unregistered."
		} >&2
	fi
done <<EOF
$(strip_comments "$UNREG")
EOF

declared_paths=$(printf '%s\n' "$declared_paths" | grep . | sort -u)

# ------------------------------------------------------------------ claims ---
# Every tracked file under userspace-dp/src/, plus userspace-dp README.md files,
# that mentions Miri at all.
claim_files=$(git ls-files -z 'userspace-dp/src/*' 'userspace-dp/*README.md' 2>/dev/null |
	xargs -0 grep -lil 'miri' 2>/dev/null | sort -u)
n_claims=$(printf '%s\n' "$claim_files" | grep -c . )

# `git ls-files` cannot see an UNTRACKED file, so a new module carrying a Miri
# claim would sweep past this census until someone committed it. Reported
# separately because it fails for YOUR checkout only -- someone else at this
# same commit sees a clean census, which is a different problem from a tracked
# file that is genuinely undeclared.
untracked_claims=$(git ls-files -z --others --exclude-standard \
	'userspace-dp/src/*' 'userspace-dp/*README.md' 2>/dev/null |
	xargs -0 grep -lil 'miri' 2>/dev/null | sort -u)
if [ -n "$untracked_claims" ]; then
	note_fail "UNTRACKED file mentions Miri -- present in your working tree but NOT in git:"
	for f in $untracked_claims; do echo "          $f" >&2; done
	{
		echo "        Remedy, pick one:"
		echo "          - \`git add\` it, then register or declare it, or"
		echo "          - remove it from your working tree."
		echo "        Do NOT add it to $UNREG: that list may only name COMMITTED paths,"
		echo "        and a declaration for a path not in the tree is itself a FAIL above."
	} >&2
fi

if [ "$n_claims" -eq 0 ]; then
	note_fail "the claim matcher discovered ZERO files mentioning Miri"
	{
		echo "        userspace-dp is known to carry Miri claims, so an empty sweep means the"
		echo "        matcher or the file list broke -- not that the claims are gone. A census"
		echo "        that sweeps an empty set and reports a clean board is the #7296 failure."
	} >&2
fi

uncovered=""
n_covered=0
for f in $claim_files; do
	if printf '%s\n' "$covered_paths" | grep -qxF "$f"; then
		n_covered=$((n_covered + 1))
		continue
	fi
	printf '%s\n' "$declared_paths" | grep -qxF "$f" && continue
	uncovered="$uncovered $f"
done

if [ -n "$uncovered" ]; then
	note_fail "UNCOVERED and undeclared -- mentions Miri, run by no registered module, declared nowhere:"
	for f in $uncovered; do echo "          $f" >&2; done
	{
		echo "        Remedy, pick one:"
		echo "          - register a module that covers it in $REGISTRY (then \`make test-miri\`"
		echo "            actually runs it, and the claim in the file becomes true), or"
		echo "          - add a line to $UNREG: '<path>  <one-line reason>' and make the file's"
		echo "            own wording say that no leg runs it."
		echo "        A comment asserting Miri coverage is NOT coverage. That equivalence is the"
		echo "        whole of #9499."
	} >&2
fi

# --------------------------------------------------------- positive control ---
# Without this, a broken matcher plus a regenerated declaration file is a green
# census over an inverted world.
if printf '%s\n' "$declared_paths" | grep -qxF "$CONTROL"; then
	note_fail "POSITIVE CONTROL $CONTROL appears in $UNREG"
	echo "        The control must be COVERED by a registered module. It may never be declared." >&2
elif ! printf '%s\n' "$covered_paths" | grep -qxF "$CONTROL"; then
	note_fail "POSITIVE CONTROL $CONTROL does not classify as COVERED"
	{
		echo "        It carries Miri claims and afxdp::types::cos:: is registered, so a census"
		echo "        that cannot see it as covered has a broken registry resolver -- and a"
		echo "        broken resolver reports every other file as uncovered or, with a"
		echo "        regenerated declaration list, reports a clean board."
	} >&2
fi

echo ""
echo "miri census: $n_claims file(s) mention Miri -- $n_covered covered by $n_registered registered module(s), $n_declared declared unregistered"
if [ "$FAIL" -ne 0 ]; then
	echo "miri census: FAILED ($FAIL problem(s))" >&2
	exit 1
fi
echo "miri census: OK"
exit 0
