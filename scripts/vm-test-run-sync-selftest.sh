#!/usr/bin/env bash
# scripts/vm-test-run-sync-selftest.sh -- #19134: reusing a vm-test-run.sh
# lane (`--name`) across trees must never re-test the previous cargo binary.
#
# cargo calls a crate fresh when no source file is newer than its artefacts,
# and the lane's target dir outlives every sync. A tree whose files carry
# OLDER mtimes than the lane's last build was therefore treated as already
# built. Hermetic apart from cargo: a mock `incus` on PATH runs the runner
# side locally (paths under /work/ rewritten into a sandbox), and each "tree"
# is a scratch git worktree holding a one-file crate that prints its VALUE.
#
# Cells:
#   - control: the trap is real on this toolchain -- build A, overwrite it with
#     an older-mtime B in place, and cargo runs A's binary.
#   - fresh lane: A builds and prints value=1.
#   - unchanged re-sync: A again under the same lane rebuilds NOTHING (the
#     ledger keeps the incremental build).
#   - older tree: B (value=2, mtimes older than A's build) under the same
#     lane recompiles and prints value=2 (the issue's case).
#   - runner-side edit: a run edits the source on the runner and builds it;
#     the next sync of the unchanged tree recompiles back to the tree.
#   - unbuilt middle sync: A built, then B synced but not built, then C (B's
#     content, older still) recompiles and prints C's value.
#   - no ledger: a lane whose ledger is gone but whose target dir is not
#     recompiles.
#   - mutation: the restamp without its dirty-file check fails the
#     runner-side-edit cell.
# Needs cargo; exits 77 (SKIP) without it.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script="$here/vm-test-run.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/vm-test-run-sync-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

if ! command -v cargo >/dev/null 2>&1; then
	echo "SKIP: cargo not installed"
	exit 77
fi

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS: $*"; }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }

mkdir -p "$tmp/bin" "$tmp/work"
cat >"$tmp/bin/incus" <<'MOCK'
#!/usr/bin/env bash
# Mock incus (#19134 selftest): the runner side runs locally, /work/ rewritten
# into $MOCK_ROOT, `chown ... runner:runner` dropped (the selftest's own user
# owns everything).
case "${1:-}" in
info) echo "Status: RUNNING"; exit 0 ;;
exec) shift 2; [[ "${1:-}" == -- ]] && shift ;;
*) exit 90 ;;
esac
rewrite() {
	local body=${1//\/work\//$MOCK_ROOT/work/}
	printf '%s' "${body//chown -R runner:runner/true}"
}
case "${1:-}" in
test)
	[[ "$*" == "test -f /etc/xpf-testrunner" ]] && exit 0
	shift
	exec test "${@//\/work\//$MOCK_ROOT/work/}" ;;
find) exit 0 ;;
systemd-detect-virt) echo kvm; exit 0 ;;
bash) [[ "${2:-}" == -c || "${2:-}" == -lc ]] || exit 92; exec bash -c "$(rewrite "$3")" ;;
su)
	if [[ "${2:-}" == - ]]; then
		[[ "${3:-}" == runner && "${4:-}" == -c ]] || exit 91; exec bash -c "$(rewrite "$5")"
	fi
	[[ "${2:-}" == runner && "${3:-}" == -c ]] || exit 94; exec bash -c "$(rewrite "$4")" ;;
*) exit 93 ;;
esac
MOCK
chmod +x "$tmp/bin/incus"

# make_tree <dir> <value> <mtime>: a git worktree holding a crate that prints
# value=<value>, every file stamped <mtime>.
make_tree() {
	mkdir -p "$1/src"
	git init -q "$1"
	cat >"$1/Cargo.toml" <<'TOML'
[package]
name = "stalefix19134"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]
TOML
	printf 'const VALUE: u32 = %s;\nfn main() {\n    println!("value={}", VALUE);\n}\n' "$2" >"$1/src/main.rs"
	(cd "$1" && cargo generate-lockfile --offline >/dev/null 2>&1)
	touch -d "$3" "$1/Cargo.toml" "$1/Cargo.lock" "$1/src/main.rs"
}
make_tree "$tmp/A" 1 "2020-06-01 00:00:00"
make_tree "$tmp/B" 2 "2001-01-01 00:00:00"
make_tree "$tmp/C" 2 "1999-01-01 00:00:00"

# lane <script> <tree> <name> <out> <command>: run the command on the mock
# runner from <tree>, syncing it into lane <name>.
lane() {
	(cd "$2" && PATH="$tmp/bin:$PATH" MOCK_ROOT="$tmp" CARGO_NET_OFFLINE=true \
		bash "$1" --runner mock:runner --name "$3" -- "$5") >"$4" 2>&1 || true
}
run_cmd='cargo run --offline 2>&1'
compiled() { grep -q 'Compiling stalefix19134' "$1"; }
printed() { grep -qx "value=$2" "$1"; }

# control: the trap itself, without vm-test-run.sh.
cp -a "$tmp/A" "$tmp/ctl"
(cd "$tmp/ctl" && CARGO_TARGET_DIR="$tmp/ctl-target" cargo run --offline >/dev/null 2>&1)
cp -a "$tmp/B/src/main.rs" "$tmp/ctl/src/main.rs" # cp -a keeps B's older mtime
(cd "$tmp/ctl" && CARGO_TARGET_DIR="$tmp/ctl-target" cargo run --offline) >"$tmp/ctl.out" 2>&1 || true
if printed "$tmp/ctl.out" 1; then
	ok "control: with A's build in place an older-mtime B runs A's binary (value=1): the trap is real"
else
	bad "control: cargo did not serve the stale binary; the cells below prove nothing ($(tr '\n' '|' <"$tmp/ctl.out"))"
fi

# fresh lane, then the unchanged re-sync.
lane "$script" "$tmp/A" one "$tmp/a1.out" "$run_cmd"
if compiled "$tmp/a1.out" && printed "$tmp/a1.out" 1; then ok "fresh lane: A compiles and prints value=1"; else bad "fresh lane: $(tr '\n' '|' <"$tmp/a1.out")"; fi
lane "$script" "$tmp/A" one "$tmp/a2.out" "$run_cmd"
if ! compiled "$tmp/a2.out" && printed "$tmp/a2.out" 1; then
	ok "unchanged re-sync: A again rebuilds nothing and prints value=1"
else
	bad "unchanged re-sync: $(tr '\n' '|' <"$tmp/a2.out")"
fi

# the issue's case: an older-mtime B under the same lane.
lane "$script" "$tmp/B" one "$tmp/b1.out" "$run_cmd"
if compiled "$tmp/b1.out" && printed "$tmp/b1.out" 2; then
	ok "older tree: B under A's lane recompiles and prints value=2"
else
	bad "older tree: B under A's lane did not rebuild ($(tr '\n' '|' <"$tmp/b1.out"))"
fi

# runner-side edit: the run edits main.rs on the runner and builds it; the next
# sync of the unchanged B must recompile back to value=2.
# runner_edit <script> <lane> <out>
runner_edit() {
	lane "$1" "$tmp/B" "$2" "$3.prep" "$run_cmd"
	lane "$1" "$tmp/B" "$2" "$3.edit" "sed -i 's/= 2;/= 9;/' src/main.rs && $run_cmd"
	lane "$1" "$tmp/B" "$2" "$3" "$run_cmd"
}
runner_edit "$script" edit "$tmp/e.out"
if printed "$tmp/e.out.edit" 9 && compiled "$tmp/e.out" && printed "$tmp/e.out" 2; then
	ok "runner-side edit: after a run built an edited source, the next sync recompiles to the tree (value=2)"
else
	bad "runner-side edit: edit=$(tr '\n' '|' <"$tmp/e.out.edit") next=$(tr '\n' '|' <"$tmp/e.out")"
fi

# unbuilt middle sync: A built, B synced without a build, then C (B's content).
lane "$script" "$tmp/A" mid "$tmp/m1.out" "$run_cmd"
lane "$script" "$tmp/B" mid "$tmp/m2.out" "true"
lane "$script" "$tmp/C" mid "$tmp/m3.out" "$run_cmd"
if compiled "$tmp/m3.out" && printed "$tmp/m3.out" 2; then
	ok "unbuilt middle sync: C after an unbuilt B recompiles and prints value=2"
else
	bad "unbuilt middle sync: $(tr '\n' '|' <"$tmp/m3.out")"
fi

# no ledger: the lane's ledger is gone but its target dir is not.
lane "$script" "$tmp/A" bare "$tmp/n1.out" "$run_cmd"
rm -f "$tmp/work/bare/.xpf-src-ledger.json"
lane "$script" "$tmp/B" bare "$tmp/n2.out" "$run_cmd"
if compiled "$tmp/n2.out" && printed "$tmp/n2.out" 2; then
	ok "no ledger: a lane with a build but no ledger recompiles (value=2)"
else
	bad "no ledger: $(tr '\n' '|' <"$tmp/n2.out")"
fi

# mutation: drop the dirty-file check; the runner-side-edit cell must fail.
sed 's/        if entry is None or entry\[0\] != digest(path):/        if False:/' "$script" >"$tmp/no-dirty.sh"
if cmp -s "$script" "$tmp/no-dirty.sh"; then
	bad "mutation no-dirty: the anchor was not found"
else
	runner_edit "$tmp/no-dirty.sh" edit-mutant "$tmp/em.out"
	if printed "$tmp/em.out" 2 && compiled "$tmp/em.out"; then
		bad "mutation no-dirty: the runner-side-edit cell still passed; it cannot see the defect"
	else
		ok "mutation no-dirty: without the dirty-file check the edited binary is re-tested (cell fails)"
	fi
fi

echo "vm-test-run sync selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
