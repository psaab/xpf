#!/bin/sh
# scripts/harness-census.sh — reachability census over the RUNNABLE HARNESSES
# (#8302, design step 2).
#
# WHAT IT ASSERTS
#
#   Every runnable harness under test/incus/ (and scripts/userspace-*.sh) is
#   either INVOKED by a Makefile recipe — directly, or transitively through
#   another harness that is itself invoked — or DECLARED unreached with a
#   one-line reason in test/incus/HARNESSES.unreached.
#
# WHY IT EXISTS
#
#   scripts/run-selftests.sh carries three censuses (#8153 interpreter, #7296
#   self-test, #8278 python) and each one exists because a test accumulated on
#   disk that NOTHING ran. One layer up — the cluster/measurement harnesses —
#   there was no census at all, and on the day this landed 28 of the 41
#   runnable harnesses were reached by nothing. 15 of those are real gates
#   (mouse-latency matrix + rep + same-class, FBF steering, new-flow ceiling,
#   persistent-NAT failover, DHCP-lease failover, cc-rollback, wg-interop,
#   reverse-key collision, and the CoS/fairness sweeps). This is the #7296
#   shape one layer up.
#
#   The 28 is measured by this script, not asserted: the design that specified
#   it counted 19 of 33 and credited apply-cos-config.sh, fairness-harness.sh,
#   fairness-cos-class-sweep.sh and cos-be-contention-harness.sh as reached
#   transitively. None of them is. apply-cos-config.sh's only appearance in a
#   REACHED file is a `#` comment in with-cluster.sh; the other three are named
#   only from callers that are themselves unreached, or inside an `echo` string
#   in target-services.sh. That is the census's own subject matter arriving in
#   its specification, which is why the four shapes below are cells and not
#   prose.
#
# FALSIFIABILITY — what this reports when the property is FALSE
#
#   * A harness that silently becomes unreached tomorrow (its Makefile recipe
#     is deleted, or its only caller is itself dropped from the Makefile) is
#     printed by path under "UNREACHED", with a hint naming both remedies, and
#     the census exits 1. It never degrades to a warning and never defaults the
#     harness into the declared list.
#   * A NEW harness added with no recipe and no declaration is reported the
#     same way, on the first run after it lands.
#   * A declared-unreached harness that BECOMES reached is also a FAIL ("remove
#     it from HARNESSES.unreached"): the declared list is only allowed to
#     shrink, so it cannot be used to re-hide a harness later.
#   * If the discovery glob matches ZERO harnesses the census FAILS. A census
#     that sweeps an empty set and reports a clean board is the failure mode
#     #7296 guards against, and it is the one an inverted matcher produces.
#   * If the "is it invoked" matcher breaks so that nothing is ever reached,
#     the POSITIVE CONTROL trips by name (test/incus/test-failover.sh is
#     invoked by `make test-failover` and must classify REACHED). Without it, a
#     broken matcher plus a regenerated HARNESSES.unreached is a green census
#     over an inverted world — every harness "declared unreached", nothing
#     reported. The control may never appear in the declared list.
#
#   It is hermetic: a pure file scan. No cluster, no incus, no network, no
#   build. "The measurement did not happen" is therefore not a state it can be
#   in; it either scans the tree or fails to start.
#
# WHAT COUNTS AS AN INVOCATION
#
#   A PATH TOKEN ending in `/<basename>` whose first character — after a
#   leading `VAR=` and any quotes are stripped — is one of `.  /  $  ~`.
#   So `./test/incus/x.sh`, `bash ./test/incus/x.sh`, `"${SCRIPT_DIR}/x.sh"`
#   and `WC="${SCRIPT_DIR}/x.sh"` all count. A BARE relative path counts only
#   when an interpreter word runs it (`sh scripts/run-selftests.sh`, the form
#   this Makefile uses for the selftest runner) — never on its own, which is
#   shape 4 below.
#
#   Four shapes that LOOK like registration and do NOT count. Each is a real
#   instance in this tree and each is a cell in harness-census-selftest.sh:
#
#     1. named only in a `#` COMMENT
#        (Makefile: "Run it after touching test-mouse-latency.sh.")
#     2. matched only via a DIFFERENT TARGET's name
#        (`test-fbf-steering-lib` runs the selftest, not test-fbf-steering.sh)
#        — a target name can never end in `/<basename>`, and the needle carries
#        its `.sh`, so a stem match cannot creep in.
#     3. named only under `bash -n` / `shellcheck` — lint-reachable,
#        run-unreachable (Makefile: `bash -n ./test/incus/newflow-ceiling-harness.sh`)
#     4. a BARE relative path in a lint list
#        (run-selftests.sh's SH_SCRIPTS holds `test/incus/test-fbf-steering.sh`
#        with no `./`, fed only to `$interp -n`). This is the fourth shape and
#        is why the matcher requires a `.`/`/`/`$`/`~`-rooted path rather than
#        any mention of the basename.
#
#   A `*-selftest.sh` never CONFERS reachability either. mouse-elephant-selftest.sh
#   invokes test-mouse-latency.sh against a fake iperf3; that exercises the
#   script under mocks, it does not run the gate. Selftests are covered by the
#   #7296 census and are neither classified nor scanned here.
#
#   Two deliberate over-approximations, both erring toward RED (a human
#   resolves a false unreached; a false REACHED would hide the defect):
#   assigning a harness path to a variable counts as invoking it, and a line
#   containing a lint call is dropped whole.
#
# USAGE
#   sh scripts/harness-census.sh            # census this tree
#   Every input is overridable by environment variable so the self-test can
#   point it at a fixture tree; see the parameter block below.
set -u

# shellcheck disable=SC1007
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1007
DEFAULT_ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)

# ── parameters (env-overridable so the self-test can drive a fixture tree) ──
ROOT=${CENSUS_ROOT:-$DEFAULT_ROOT}
cd "$ROOT" || { echo "FATAL: cannot cd to $ROOT" >&2; exit 2; }

MAKEFILE=${CENSUS_MAKEFILE:-Makefile}
UNREACHED_FILE=${CENSUS_UNREACHED:-test/incus/HARNESSES.unreached}
POSITIVE_CONTROL=${CENSUS_POSITIVE_CONTROL:-test/incus/test-failover.sh}

# Files classified as runnable harnesses (minus the named libraries and the
# *-selftest.sh files).
HARNESS_GLOBS=${CENSUS_HARNESS_GLOBS:-"test/incus/*.sh scripts/userspace-*.sh"}

# Files whose bodies are scanned for transitive invocations. A superset of the
# harnesses: a library or a plain script can be the link in the chain.
SCAN_GLOBS=${CENSUS_SCAN_GLOBS:-"test/incus/*.sh scripts/*.sh"}

# Libraries are exempt because they are SOURCED, not run. The exemption is a
# NAMED LIST, not a `*-lib.sh` wildcard: a new library has to be declared here,
# and the census fails if a *-lib.sh appears on disk without being listed (a
# wildcard would let a runnable harness be exempted by renaming it).
if [ "${CENSUS_LIBRARIES+set}" = set ]; then
	LIBRARIES=$CENSUS_LIBRARIES
else
	LIBRARIES="
test/incus/cluster-cell.sh
test/incus/cluster-env.sh
test/incus/cluster-lock.sh
test/incus/cos-apply-lib.sh
test/incus/deploy-lib.sh
test/incus/fbf-steering-lib.sh
test/incus/failover-client-lib.sh
test/incus/host-inbound-lib.sh
test/incus/iperf-throughput-lib.sh
test/incus/mouse-elephant-lib.sh
test/incus/newflow-ceiling-lib.sh
test/incus/screen-probe-lib.sh
test/incus/wire-gate-lib.sh
test/incus/wire-config-snapshot-lib.sh
test/incus/target-services.sh
"
fi

# The lists above are written one-per-line for readability; collapse them to
# space-separated words so the `case " $list " in *" $x "*` membership test has
# a uniform separator. Unquoted expansion is deliberate: it word-splits.
# shellcheck disable=SC2116,SC2086
LIBRARIES=$(echo $LIBRARIES)

FAIL=0
note_fail() { echo "  FAIL: $*" >&2; FAIL=$((FAIL + 1)); }
note_pass() { echo "  PASS: $*"; }

in_list() { # in_list <needle> <space-separated list>
	case " $2 " in
	*" $1 "*) return 0 ;;
	esac
	return 1
}

# strip_comments — drop whitespace-anchored `#` comments. Anchored on
# whitespace (not the bare `s/#.*//` the older censuses use) so a parameter
# expansion like ${path#*/} does not truncate the line and hide a real
# invocation later on it.
strip_comments() { # census-guard: comment-strip
	sed -e 's/^[[:space:]]*#.*$//' -e 's/[[:space:]]#.*$//'
}

# drop_lint_lines — a line whose only contact with a script is a SYNTAX CHECK
# is not an invocation. Drops `bash -n` / `sh -n` / `shellcheck` lines whole.
drop_lint_lines() { # census-guard: lint-drop
	grep -vE '(^|[^[:alnum:]_.-])(ba|da|z|k)?sh[[:space:]]+-n[[:space:]]|shellcheck' || true
}

# makefile_recipe_code — the RECIPE lines only (leading TAB), with simple
# variable references expanded. Target lines, .PHONY lines and comments are not
# recipes and can never invoke anything: that is defence against shape 2.
# $(CLUSTER_SETUP) holds `... ./test/incus/cluster-setup.sh` and is only ever
# named from a recipe, so without the expansion cluster-setup.sh would be a
# false unreached.
makefile_recipe_code() {
	[ -f "$MAKEFILE" ] || return 0
	awk '
	/^\t/ {   # census-guard: recipe-lines-only
		line = $0
		for (pass = 0; pass < 3; pass++)
			for (n in var) {
				gsub("\\$\\(" n "\\)", var[n], line)
				gsub("\\$\\{" n "\\}", var[n], line)
			}
		print line
		next
	}
	/^[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[:?+]*=/ {
		eq = index($0, "=")
		name = substr($0, 1, eq - 1)
		val = substr($0, eq + 1)
		gsub(/[[:space:]:?+]+$/, "", name)
		gsub(/^[[:space:]]+/, "", val)
		gsub(/&/, "\\&", val)
		var[name] = val
	}
	' "$MAKEFILE" | strip_comments | drop_lint_lines
}

# invoked_basenames — every basename this code INVOKES, one per line.
#
# A token counts only when it is a ROOTED PATH ending in `/<something>.sh`:
# after a leading `VAR=` and any quotes are stripped, its first character must
# be one of `.  /  $  ~`. That single rule is what separates an invocation from
# a mention, and it is what blocks shapes 2 and 4 — a Makefile TARGET name is
# not a path at all, and `test/incus/x.sh` with no `./` is a bare list entry
# that only ever reaches `$interp -n`.
invoked_basenames() {
	awk '
	{
		n = split($0, tok, /[[:space:]]+/)
		for (i = 1; i <= n; i++) {
			t = tok[i]
			sub(/^[A-Za-z_][A-Za-z0-9_]*=/, "", t)      # VAR=<path> counts
			sub(/^["'"'"'`(]+/, "", t)
			sub(/["'"'"'`);,]+$/, "", t)
			if (t !~ /^[.\/$~]/) {                      # census-guard: rooted-path
				# A bare relative path is a LIST ENTRY (shape 4)
				# unless an interpreter word runs it: `sh
				# scripts/run-selftests.sh` is an invocation,
				# `test/incus/x.sh` alone on a line of SH_SCRIPTS
				# is not.
				if (i == 1) continue
				p = tok[i - 1]
				sub(/^["'"'"'`(]+/, "", p)
				if (p !~ /^(sh|bash|dash|ksh|zsh|source|exec|env|time|sudo|\.)$/) continue
			}
			m = split(t, part, "/")
			if (m < 2) continue
			b = part[m]
			if (b ~ /\.sh$/) print b
		}
	}
	' | sort -u
}

# is_invoked <harness-path> <invoked-basename-set> <caller-code>
#
# EXACT BASENAME equality against the set invoked_basenames() extracted. The
# needle carries its `.sh`, so `test-fbf-steering-lib` cannot satisfy
# `test-fbf-steering.sh`. Replacing this with a STEM SUBSTRING search over the
# raw caller code ($3) is the naive census — `grep test-fbf-steering Makefile`
# — which is the implementation that scores shape 2 as registered, and is the
# mutation harness-census-selftest.sh applies to prove this line has power.
is_invoked() { # census-guard: invocation-policy
	in_list "${1##*/}" "$2"
}

# code_of <path> — the invocable body of a file: comments stripped, lint lines
# dropped.
code_of() {
	[ -f "$1" ] && strip_comments <"$1" | drop_lint_lines
}

# ── 1. discover and classify ──
harnesses=""
libs_on_disk=""
for g in $HARNESS_GLOBS; do
	for f in $g; do
		[ -f "$f" ] || continue
		case "$f" in
		*-selftest.sh) continue ;;
		esac
		case "$f" in
		*-lib.sh) in_list "$f" "$libs_on_disk" || libs_on_disk="$libs_on_disk $f" ;;
		esac
	done
done
for g in $HARNESS_GLOBS; do
	for f in $g; do
		[ -f "$f" ] || continue
		case "$f" in
		*-selftest.sh) continue ;;
		esac
		in_list "$f" "$LIBRARIES" && continue
		in_list "$f" "$harnesses" || harnesses="$harnesses $f"
	done
done

n_harnesses=$(printf '%s\n' $harnesses | grep -c . || true)
if [ "$n_harnesses" -eq 0 ]; then
	# The empty sweep. A census that finds no harnesses has not proved anything
	# about the tree; it has proved its own glob is wrong. Never green.
	note_fail "harness discovery matched ZERO harnesses under: $HARNESS_GLOBS (the glob is wrong; a census over an empty set is not a pass)"
	echo ""
	echo "harness census: FAILED ($FAIL problem(s))" >&2
	exit 1
fi

# ── 2. the library exemption is a named list, and the list must not rot ──
for l in $LIBRARIES; do
	[ -f "$l" ] || note_fail "declared library does not exist: $l (stale entry in the census's LIBRARIES list)"
done
for l in $libs_on_disk; do
	in_list "$l" "$LIBRARIES" ||
		note_fail "undeclared library on disk: $l (add it to LIBRARIES in $0, or it is a harness and needs a recipe)"
done

# ── 3. reachability, transitively, from the Makefile recipes ──
scannable=""
for g in $SCAN_GLOBS $HARNESS_GLOBS; do
	for f in $g; do
		[ -f "$f" ] || continue
		case "$f" in
		*-selftest.sh) continue ;;   # a selftest exercises under mocks; it does not run the gate
		esac
		in_list "$f" "$scannable" || scannable="$scannable $f"
	done
done

root_code=$(makefile_recipe_code)
root_names=$(printf '%s\n' "$root_code" | invoked_basenames | tr '\n' ' ')
reached=""
frontier=""
for f in $scannable; do
	if is_invoked "$f" "$root_names" "$root_code"; then
		reached="$reached $f"
		frontier="$frontier $f"
	fi
done

# Transitive closure: a harness invoked by a harness that is itself invoked is
# reached. Bounded by the scannable set, so a mutually-calling cluster
# (cos-simul-load-smoke.sh <-> cos-gate1-*.sh) terminates -- and stays
# UNREACHED, because nothing in the cluster is a Makefile root.
while [ -n "${frontier# }" ]; do
	next=""
	for caller in $frontier; do
		caller_code=$(code_of "$caller")
		[ -n "$caller_code" ] || continue
		caller_names=$(printf '%s\n' "$caller_code" | invoked_basenames | tr '\n' ' ')
		for f in $scannable; do
			in_list "$f" "$reached" && continue
			if is_invoked "$f" "$caller_names" "$caller_code"; then
				reached="$reached $f"
				next="$next $f"
			fi
		done
	done
	frontier=$next
	[ -n "${frontier# }" ] || break
done

# ── 4. positive control ──
# If the matcher is broken so that nothing is ever reached, this trips by name
# rather than the census reporting a clean sweep of an inverted world.
if in_list "$POSITIVE_CONTROL" "$reached"; then
	note_pass "positive control: $POSITIVE_CONTROL classifies REACHED"
else
	note_fail "positive control FAILED: $POSITIVE_CONTROL is invoked by a Makefile recipe but classified UNREACHED -- the invocation matcher is broken, so every verdict below is untrustworthy"
fi

# ── 5. the declared-unreached list ──
declared=""
if [ -f "$UNREACHED_FILE" ]; then
	while IFS= read -r line; do
		case "$line" in
		'#'* | '') continue ;;
		esac
		path=${line%%[ 	]*}
		reason=${line#"$path"}
		reason=$(printf '%s' "$reason" | sed 's/^[ 	]*//')
		[ -n "$path" ] || continue
		if [ -z "$reason" ]; then
			note_fail "$UNREACHED_FILE: $path is declared with NO reason (a declaration without a reason is a suppression)"
		fi
		if [ ! -f "$path" ]; then
			note_fail "$UNREACHED_FILE: $path does not exist (stale declaration -- delete the line)"
			continue
		fi
		if ! in_list "$path" "$harnesses"; then
			note_fail "$UNREACHED_FILE: $path is not a runnable harness (it is a library, a self-test, or outside the census scope)"
			continue
		fi
		if [ "$path" = "$POSITIVE_CONTROL" ]; then
			note_fail "$UNREACHED_FILE: $path is the census's POSITIVE CONTROL and may never be declared unreached"
			continue
		fi
		if in_list "$path" "$reached"; then
			note_fail "$UNREACHED_FILE: $path IS reached now -- delete the line (this list is only allowed to shrink)"
			continue
		fi
		declared="$declared $path"
	done <"$UNREACHED_FILE"
else
	note_fail "$UNREACHED_FILE is missing (the declared-unreached list is part of the gate, not optional)"
fi

# ── 6. the verdict ──
# CENSUS_VERBOSE=1 lists the reached set too. Useful when authoring or auditing
# HARNESSES.unreached; the verdict does not depend on it.
if [ "${CENSUS_VERBOSE:-0}" = "1" ]; then
	echo "  reached (transitively, from a Makefile recipe):"
	for f in $harnesses; do in_list "$f" "$reached" && echo "          $f"; done
fi

undeclared=""
n_reached=0
n_declared=0
for f in $harnesses; do
	if in_list "$f" "$reached"; then
		n_reached=$((n_reached + 1))
	elif in_list "$f" "$declared"; then
		n_declared=$((n_declared + 1))
	else
		undeclared="$undeclared $f"
	fi
done

if [ -n "$undeclared" ]; then
	# #9006: split the UNTRACKED case out, because the two need OPPOSITE
	# remedies and the generic text sends the untracked case to the wrong one.
	#
	# The census scans the FILESYSTEM, which is correct -- a harness you have
	# added and not yet committed is exactly what it should catch. But an
	# uncommitted scratch script in test/incus/ then fails a shared gate for
	# your checkout only, under a message asserting "a harness was added or a
	# recipe removed", which points at recent commits. Worse, one of the two
	# printed remedies is actively wrong for it: adding an untracked path to
	# $UNREACHED_FILE trips the separate check that FAILS a declaration naming
	# a path not in the tree, so following the instructions produces a second,
	# different failure.
	#
	# HERMETICITY. This file's contract is "a pure file scan ... it either
	# scans the tree or fails to start", and that is preserved exactly: git is
	# used ONLY to refine the remedy TEXT, never the verdict, never the exit
	# status, and never whether the scan runs. With no git on PATH -- which is
	# the case in the selftest's restricted-PATH leg, where PATH holds only
	# sh grep sed cut sort awk wc -- every path falls through to the original
	# message and the census behaves bit-identically to before this change.
	untracked=""
	tracked=""
	if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
		for f in $undeclared; do
			if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
				tracked="$tracked $f"
			else
				untracked="$untracked $f"
			fi
		done
	else
		tracked="$undeclared"
	fi

	if [ -n "$untracked" ]; then
		note_fail "UNTRACKED harness -- present in your working tree but NOT in git:"
		for f in $untracked; do echo "          $f" >&2; done
		{
			echo "        The census scans the working tree, so an uncommitted harness fails it"
			echo "        for your checkout only. Someone else at this same commit sees a clean"
			echo "        census, which is why this is reported separately."
			echo "        Remedy, pick one:"
			echo "          - \`git add\` it and then register it (recipe or declaration), or"
			echo "          - remove it from your working tree."
			echo "        Do NOT add it to $UNREACHED_FILE: that list may only name COMMITTED"
			echo "        paths, and a declaration for a path not in the tree is itself a FAIL."
		} >&2
	fi

	if [ -n "$tracked" ]; then
		note_fail "UNREACHED and undeclared -- invoked by no Makefile recipe, and not declared in $UNREACHED_FILE:"
		for f in $tracked; do echo "          $f" >&2; done
		{
			echo "        Remedy, pick one:"
			echo "          - add a Makefile recipe that runs it (then it is a gate someone can run), or"
			echo "          - add a line to $UNREACHED_FILE: '<path>  <one-line reason>'"
			echo "        A mention in a comment, a similarly-named target, a 'bash -n' lint,"
			echo "        or a bare relative path in a lint list does NOT count as an invocation."
		} >&2
	fi
fi

echo ""
echo "harness census: $n_harnesses runnable harnesses -- $n_reached reached, $n_declared declared unreached"
if [ "$FAIL" -ne 0 ]; then
	echo "harness census: FAILED ($FAIL problem(s))" >&2
	exit 1
fi
echo "harness census: OK"
exit 0
