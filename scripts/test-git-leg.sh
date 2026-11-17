#!/usr/bin/env bash
# scripts/test-git-leg.sh -- #19080: the Go tests that need a git checkout.
#
# Runner lanes sync the tree WITHOUT .git (scripts/vm-test-run.sh), so these
# tests skip there, naming this leg (internal/testguard.RequireGitCheckout).
# They run here, in a lane that syncs a shallow repo: HEAD, its history down
# to the merge-base with origin/master, and refs/remotes/origin/master at that
# merge-base:
#
#   scripts/vm-test-run.sh --with-git -- make test-git-leg
#
# The leg runs with XPF_REQUIRE_GIT=1, under which a missing checkout FAILS
# the tests instead of skipping them, and it requires each named test to PASS:
# a skip, a failure, or a test that did not run at all fails the leg. A leg
# that exists to run these tests must not pass by not running them.
#
# Without a git checkout the script exits 77 (SKIP, named) unless
# XPF_REQUIRE_GIT=1 (`make test-git-leg` sets it), when it exits 2.
#
# Never use --with-git in a mutation lane: a mutation sandbox must contain no
# git metadata (vm-test-run.sh refuses it under XPF_MUTATION_LANE=1).
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

# Each test, by package. Keep in step with the RequireGitCheckout calls.
GIT_LEG_TESTS=(
	"./pkg/refactoraudit/ TestGlobalHeatmapFreshnessAdvisory"
	"./pkg/refactoraudit/ TestGeneratorDeterministic"
	"./pkg/refactoraudit/ TestAuditedPathPredicateAgreesWithGenerator"
	"./pkg/refactoraudit/ TestTouchedFileCrossedModularityThreshold"
	"./pkg/config/ TestNoTrackedFileCarriesARealClusterKey18744"
	"./pkg/dataplane/ TestFreshnessGateRejectsHandRegeneratedManifest13963"
)

if [[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" != true ]]; then
	if [[ "${XPF_REQUIRE_GIT:-}" == 1 ]]; then
		echo "test-git-leg: FAIL: XPF_REQUIRE_GIT=1 but this is not a git work tree; run it as scripts/vm-test-run.sh --with-git -- make test-git-leg (#19080)" >&2
		exit 2
	fi
	echo "test-git-leg: SKIP: not a git work tree; run it as scripts/vm-test-run.sh --with-git -- make test-git-leg (#19080)"
	exit 77
fi

declare -A pkgs=()
names=()
for row in "${GIT_LEG_TESTS[@]}"; do
	pkgs[${row%% *}]=1
	names+=("${row#* }")
done
run_re="^($(IFS='|'; echo "${names[*]}"))\$"
# #19040: honour TMPDIR; create the shared default only when it is unset.
out="$({ [ -n "${TMPDIR:-}" ] || mkdir -p /var/worktrees/.cache/tmpdir; } && mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/test-git-leg.XXXXXX")" || exit 2
trap 'rm -f "$out"' EXIT

echo "test-git-leg: HEAD $(git rev-parse --short HEAD), origin/master $(git rev-parse --short origin/master 2>/dev/null || echo '<none>'), shallow=$(git rev-parse --is-shallow-repository)"
XPF_REQUIRE_GIT=1 bash ./scripts/testguard-run.sh go test -count=1 -json -run "$run_re" "${!pkgs[@]}" >"$out" 2>&1
go_rc=$?

python3 -I - "$out" "$go_rc" "${names[@]}" <<'PY'
import json, sys

path, go_rc, names = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
final, output, build_failed = {}, {}, False
for line in open(path, errors="replace"):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if e.get("Action") == "build-fail" or e.get("FailedBuild"):
        build_failed = True
    test = e.get("Test")
    if not test or "/" in test:
        continue
    if e.get("Action") == "output":
        output.setdefault(test, []).append(e.get("Output", ""))
    elif e.get("Action") in ("pass", "fail", "skip"):
        final[test] = e["Action"]
bad = 0
for name in names:
    verdict = final.get(name, "did not run")
    print(f"test-git-leg: {name}: {verdict.upper() if verdict != 'did not run' else verdict}")
    if verdict != "pass":
        bad += 1
        for chunk in output.get(name, [])[-12:]:
            sys.stdout.write("    " + chunk)
if build_failed:
    print("test-git-leg: FAIL: a package did not build")
    bad += 1
if bad == 0 and go_rc != 0:
    print(f"test-git-leg: FAIL: go test exited {go_rc} with every named test passing")
    bad += 1
passed = sum(1 for name in names if final.get(name) == "pass")
print(f"test-git-leg: {'PASS' if bad == 0 else 'FAIL'}: {passed}/{len(names)} passed")
sys.exit(1 if bad else 0)
PY
