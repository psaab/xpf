#!/bin/sh
# ci-tooling-check-selftest.sh (#16197): prove the advisory tooling
# leg reds on a seeded Python/shell failure in the covered subset,
# reds on ran==0, reds on an unexpected skip, and greens on the
# pinned baseline. Hermetic fixture copy of the real tree; SKIPs
# (77) without the pinned shellcheck on PATH or via SHELLCHECK.
set -u

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

PIN=0.11.0
bin=${SHELLCHECK:-}
if [ -z "$bin" ] && command -v shellcheck >/dev/null 2>&1; then
	bin=$(command -v shellcheck)
fi
if [ -z "$bin" ]; then
	echo "SKIP: shellcheck not installed"
	exit 77
fi
ver=$("$bin" --version 2>/dev/null | sed -n 's/^version: //p' | head -1)
if [ "$ver" != "$PIN" ]; then
	echo "SKIP: shellcheck is $ver, want $PIN"
	exit 77
fi
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 77; }

SCRATCH_BASE=${TMPDIR:-/var/worktrees/.cache/tmpdir}
if ! mkdir -p "$SCRATCH_BASE" 2>/dev/null; then
	SCRATCH_BASE=/tmp
fi
SCRATCH=$SCRATCH_BASE/xpf-ci-tooling-selftest.$$
trap 'rm -rf "$SCRATCH"' EXIT INT TERM
mkdir -p "$SCRATCH/fixture"

# Fixture = scratch copy of the read set the covered legs touch:
# everything under scripts/ (shellcheck list + python tests and
# their subjects), test/ + userspace-dp/build_support (shellcheck
# list), docs/install-images.md, debian/ and Makefile (read by the
# python tests). tests that read other paths build synthetic
# fixtures, so copying more would slow the selftest without
# covering more of the leg. Mutations touch only this copy.
(
	cd "$ROOT" || exit 1
	mkdir -p "$SCRATCH/fixture/docs"
	for d in scripts test debian; do
		mkdir -p "$SCRATCH/fixture/$d"
		tar -cf - "$d" | (cd "$SCRATCH/fixture" && tar -xf -)
	done
	mkdir -p "$SCRATCH/fixture/userspace-dp/build_support"
	cp userspace-dp/build_support/dp-toolchain.sh \
		"$SCRATCH/fixture/userspace-dp/build_support/"
	cp docs/install-images.md "$SCRATCH/fixture/docs/"
	cp Makefile "$SCRATCH/fixture/"
	# test_skill_file_push_lint.py checks the shipped skill tree.
	mkdir -p "$SCRATCH/fixture/.claude"
	tar -cf - .claude/skills | (cd "$SCRATCH/fixture" && tar -xf -)
)

run_leg() {
	# $1 = log file. Everything else comes from the caller's env.
	(
		cd "$SCRATCH/fixture" || exit 1
		SHELLCHECK=$bin sh scripts/ci_tooling_check.sh
	) >"$1" 2>&1
}

expect() {
	# $1 = description, $2 = log, $3 = expected rc (0 or 1), $4 = egrep pattern
	desc=$1 log=$2 wantrc=$3 pat=$4
	gotrc=$5
	if [ "$gotrc" -ne "$wantrc" ]; then
		echo "FAIL: $desc (exit $gotrc, want $wantrc)"; cat "$log"; exit 1
	fi
	if ! grep -E -q "$pat" "$log"; then
		echo "FAIL: $desc (missing /$pat/)"; cat "$log"; exit 1
	fi
	echo "PASS: $desc"
}

# 1. Pinned baseline is green and publishes denominators.
run_leg "$SCRATCH/base.log"; rc=$?
expect "pinned baseline greens" "$SCRATCH/base.log" 0 \
	'TOOLING_LEG shellcheck ran=[1-9][0-9]* skipped=0 failed=0 expected_skipped=0 status=PASS' "$rc"
expect "python denominator published" "$SCRATCH/base.log" 0 \
	'TOOLING_LEG python ran=[1-9][0-9]* skipped=0 failed=0 .*expected_skipped=0 status=PASS' "$rc"

# 2. Seeded Python failure in the covered subset is red.
cat > "$SCRATCH/fixture/scripts/test_seeded_fail_16197.py" <<'EOF'
import unittest
class Seeded(unittest.TestCase):
    def test_fail(self):
        self.assertTrue(False, "seeded failure (#16197 selftest)")
if __name__ == "__main__":
    unittest.main()
EOF
run_leg "$SCRATCH/pyfail.log"; rc=$?
expect "seeded Python failure reds" "$SCRATCH/pyfail.log" 1 \
	'TOOLING_LEG python .*failed=[1-9]' "$rc"
rm "$SCRATCH/fixture/scripts/test_seeded_fail_16197.py"

# 3. Seeded shell failure in the covered subset is red.
printf '\nseeded_unclosed_quote="\n' >> "$SCRATCH/fixture/scripts/harness-census.sh"
run_leg "$SCRATCH/shfail.log"; rc=$?
expect "seeded shell failure reds" "$SCRATCH/shfail.log" 1 \
	'TOOLING_LEG shellcheck .*failed=[1-9]' "$rc"
# Restore the mutated covered file from the real tree.
cp "$ROOT/scripts/harness-census.sh" "$SCRATCH/fixture/scripts/harness-census.sh"

# 4. A Python file that runs nothing is red (ran==0 per file).
cat > "$SCRATCH/fixture/scripts/test_seeded_empty_16197.py" <<'EOF'
import unittest
class Empty(unittest.TestCase):
    pass
if __name__ == "__main__":
    unittest.main()
EOF
run_leg "$SCRATCH/empty.log"; rc=$?
# Python 3.14's unittest exits 5 (NO TESTS RAN) here, so the leg's
# generic FAIL line fires rather than its rc==0/ran==0 branch; accept
# that rendering, but require the file named in a FAIL. Cell 4b pins
# the leg's own ran==0 diagnostic via a stub transcript.
expect "empty Python file reds" "$SCRATCH/empty.log" 1 \
	'FAIL: scripts/test_seeded_empty_16197.py' "$rc"
rm "$SCRATCH/fixture/scripts/test_seeded_empty_16197.py"

# 4b. The rc==0/ran==0 branch, pinned unit-style: a stub python3
# replaying a zero-run unittest transcript must be red with the
# leg's own ran==0 diagnostic (a stub that measured nothing).
mkdir -p "$SCRATCH/stubbin"
cat > "$SCRATCH/stubbin/python3" <<'EOF'
#!/bin/sh
echo "Ran 0 tests in 0.000s"
echo ""
echo "OK"
exit 0
EOF
chmod +x "$SCRATCH/stubbin/python3"
(
	cd "$SCRATCH/fixture" || exit 1
	PATH="$SCRATCH/stubbin:/usr/bin:/bin" SHELLCHECK=$bin sh scripts/ci_tooling_check.sh
) >"$SCRATCH/zeroran.log" 2>&1; rc=$?
expect "zero-run transcript reds with ran==0 diagnostic" "$SCRATCH/zeroran.log" 1 \
	'ran=0 -- measures nothing' "$rc"

# 5. An all-skip Python file deviates from expected_skipped=0: red.
cat > "$SCRATCH/fixture/scripts/test_seeded_skip_16197.py" <<'EOF'
import unittest
class Skippy(unittest.TestCase):
    @unittest.skip("seeded skip (#16197 selftest)")
    def test_skip(self):
        pass
if __name__ == "__main__":
    unittest.main()
EOF
run_leg "$SCRATCH/skip.log"; rc=$?
expect "unexpected Python skip reds" "$SCRATCH/skip.log" 1 \
	'TOOLING_LEG python ran=[1-9][0-9]* skipped=[1-9]' "$rc"
rm "$SCRATCH/fixture/scripts/test_seeded_skip_16197.py"

# 6. Whole-leg ran==0: removing every covered Python file is red.
mkdir -p "$SCRATCH/stash"
for f in "$SCRATCH/fixture"/scripts/test_*.py "$SCRATCH/fixture"/scripts/*_test.py "$SCRATCH/fixture"/scripts/lib/test_*.py; do
	[ -f "$f" ] || continue
	mv "$f" "$SCRATCH/stash/$(basename "$f")"
done
run_leg "$SCRATCH/nopy.log"; rc=$?
expect "python ran==0 reds" "$SCRATCH/nopy.log" 1 \
	'TOOLING_LEG python ran=0 ' "$rc"
for f in "$SCRATCH"/stash/*.py; do
	[ -f "$f" ] || continue
	base=$(basename "$f")
	case "$base" in
	lib_*) : ;;
	esac
	# Restore by original location: lib tests were copied under scripts/lib.
	if [ -f "$SCRATCH/fixture/scripts/lib/$base" ] || [ "$base" = "test_load_subject.py" ]; then
		mv "$f" "$SCRATCH/fixture/scripts/lib/$base"
	else
		mv "$f" "$SCRATCH/fixture/scripts/$base"
	fi
done

# 7. Baseline again green after mutations are removed.
run_leg "$SCRATCH/final.log"; rc=$?
expect "restored baseline greens" "$SCRATCH/final.log" 0 \
	'ci_tooling_check: OK' "$rc"

echo "ci-tooling-check-selftest: OK"
