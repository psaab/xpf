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
#   - restored after build: a run edits, builds, then writes the ORIGINAL
#     bytes back (scripts/mutate-9546.py restores its mutants this way); the
#     next sync must recompile, though every byte matches the ledger.
#   - deleted after build: a run deletes a file a build script probes, and
#     builds; the next sync restores the file and must re-run the script.
#   - unbuilt middle sync: A built, then B synced but not built, then C (B's
#     content, older still) recompiles and prints C's value.
#   - no ledger: a lane whose ledger is gone but whose target dir is not
#     recompiles.
#   - artefacts ahead of the clock: the lane's build carries mtimes a day in
#     the future (a clock that stepped back after the build); a changed tree
#     must still recompile, so its stamp must clear the newest artefact.
#   - clock behind the previous sync: the ledger says the last sync was a
#     day from now; the sync must say so, clean the target dir and rebuild.
#   - mutations, each KILLED only when its cell observably runs the stale
#     build (or, for the backstop, keeps the build it must discard): no dirty
#     check at all (runner-side edit runs value=9); a
#     content-only dirty check, the pre-#19134-review shape (restored after
#     build runs value=9); no deleted-file check (deleted after build runs
#     flag=0); stamping with the plain clock (artefacts ahead runs value=1);
#     no clock backstop (the old build is reused, nothing recompiles).
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
# make_probe_tree <dir> <mtime>: a crate whose build script bakes in whether
# flag.txt exists (flag=1/0), with cargo told to re-run it when flag.txt
# changes.
make_probe_tree() {
	mkdir -p "$1/src"
	git init -q "$1"
	cat >"$1/Cargo.toml" <<'TOML'
[package]
name = "stalefix19134probe"
version = "0.0.0"
edition = "2021"
publish = false
build = "build.rs"

[workspace]
TOML
	cat >"$1/build.rs" <<'RS'
fn main() {
    println!("cargo:rerun-if-changed=flag.txt");
    let flag = if std::path::Path::new("flag.txt").exists() { 1 } else { 0 };
    println!("cargo:rustc-env=PROBE_FLAG={flag}");
}
RS
	printf 'fn main() {
    println!("flag={}", env!("PROBE_FLAG"));
}
' >"$1/src/main.rs"
	echo on >"$1/flag.txt"
	(cd "$1" && cargo generate-lockfile --offline >/dev/null 2>&1)
	touch -d "$2" "$1/Cargo.toml" "$1/Cargo.lock" "$1/build.rs" "$1/src/main.rs" "$1/flag.txt"
}
make_tree "$tmp/A" 1 "2020-06-01 00:00:00"
make_tree "$tmp/B" 2 "2001-01-01 00:00:00"
make_tree "$tmp/C" 2 "1999-01-01 00:00:00"
make_probe_tree "$tmp/D" "2010-01-01 00:00:00"

# lane <script> <tree> <name> <out> <command>: run the command on the mock
# runner from <tree>, syncing it into lane <name>.
lane() {
	(cd "$2" && PATH="$tmp/bin:$PATH" MOCK_ROOT="$tmp" CARGO_NET_OFFLINE=true \
		bash "$1" --runner mock:runner --name "$3" -- "$5") >"$4" 2>&1 || true
}
run_cmd='cargo run --offline 2>&1'
compiled() { grep -q 'Compiling stalefix19134' "$1"; }
printed() { grep -qx "value=$2" "$1"; }
flagged() { grep -qx "flag=$2" "$1"; }

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

# restored after build: edit, build, write the original bytes back, re-sync.
# runner_restore <script> <lane> <out>
runner_restore() {
	lane "$1" "$tmp/B" "$2" "$3.prep" "$run_cmd"
	# The tree's bytes by checksum, not path: the mock rewrites /work/ paths.
	local sum
	sum=$(sha256sum <"$tmp/B/src/main.rs" | cut -c1-64)
	lane "$1" "$tmp/B" "$2" "$3.edit" "sed -i 's/= 2;/= 9;/' src/main.rs && $run_cmd && sed -i 's/= 9;/= 2;/' src/main.rs && [ \"\$(sha256sum <src/main.rs | cut -c1-64)\" = $sum ] && echo restored-bytes"
	lane "$1" "$tmp/B" "$2" "$3" "$run_cmd"
}
runner_restore "$script" restore "$tmp/r.out"
if printed "$tmp/r.out.edit" 9 && grep -qx restored-bytes "$tmp/r.out.edit" && compiled "$tmp/r.out" && printed "$tmp/r.out" 2; then
	ok "restored after build: a run that built value=9 and wrote the original bytes back is followed by a recompile (value=2)"
else
	bad "restored after build: edit=$(tr '\n' '|' <"$tmp/r.out.edit") next=$(tr '\n' '|' <"$tmp/r.out")"
fi

# deleted after build: the run deletes flag.txt and builds (flag=0); the next
# sync restores flag.txt and must re-run the build script (flag=1).
# runner_delete <script> <lane> <out>
runner_delete() {
	lane "$1" "$tmp/D" "$2" "$3.prep" "$run_cmd"
	lane "$1" "$tmp/D" "$2" "$3.del" "rm flag.txt && $run_cmd"
	lane "$1" "$tmp/D" "$2" "$3" "$run_cmd"
}
runner_delete "$script" delete "$tmp/d.out"
if flagged "$tmp/d.out.prep" 1 && flagged "$tmp/d.out.del" 0 && flagged "$tmp/d.out" 1; then
	ok "deleted after build: after a run built without flag.txt, the next sync re-runs the build script (flag=1)"
else
	bad "deleted after build: prep=$(tr '\n' '|' <"$tmp/d.out.prep") del=$(tr '\n' '|' <"$tmp/d.out.del") next=$(tr '\n' '|' <"$tmp/d.out")"
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

# artefacts ahead of the clock: A built, every file of the lane's target dir
# moved a day into the future, then B (a changed tree) synced into the lane.
# runner_ahead <script> <lane> <out>
runner_ahead() {
	lane "$1" "$tmp/A" "$2" "$3.prep" "$run_cmd"
	find "$tmp/work/$2/target" -exec touch -h -d "@$(($(date +%s) + 86400))" {} +
	lane "$1" "$tmp/B" "$2" "$3" "$run_cmd"
}
runner_ahead "$script" ahead "$tmp/ah.out"
if printed "$tmp/ah.out.prep" 1 && compiled "$tmp/ah.out" && printed "$tmp/ah.out" 2; then
	ok "artefacts ahead of the clock: a changed tree still recompiles (value=2)"
else
	bad "artefacts ahead of the clock: prep=$(tr '\n' '|' <"$tmp/ah.out.prep") next=$(tr '\n' '|' <"$tmp/ah.out")"
fi

# clock behind the previous sync: the ledger's last sync is a day from now.
# runner_clock_back <script> <lane> <out>
runner_clock_back() {
	lane "$1" "$tmp/A" "$2" "$3.prep" "$run_cmd"
	python3 -I -c 'import json, sys, time
p = sys.argv[1]
d = json.load(open(p))
d["last_sync_ns"] = time.time_ns() + 86400 * 10**9
json.dump(d, open(p, "w"))' "$tmp/work/$2/.xpf-src-ledger.json"
	lane "$1" "$tmp/A" "$2" "$3" "$run_cmd"
}
runner_clock_back "$script" back "$tmp/bk.out"
if grep -q 'behind the previous sync; cleaning' "$tmp/bk.out" && compiled "$tmp/bk.out" && printed "$tmp/bk.out" 1; then
	ok "clock behind the previous sync: the sync says so, cleans the target dir, and the run rebuilds (value=1)"
else
	bad "clock behind the previous sync: $(tr '\n' '|' <"$tmp/bk.out")"
fi

# mutate <name> <sed expr> <cell function> <lane> <stale-value check>: the
# mutant is KILLED only when its cell actually runs the STALE binary; any
# other outcome (a build error, a missing anchor) is not a kill.
mutate() {
	sed "$2" "$script" >"$tmp/$1.sh"
	if cmp -s "$script" "$tmp/$1.sh"; then
		bad "mutation $1: the anchor was not found"
		return
	fi
	"$3" "$tmp/$1.sh" "$4" "$tmp/$1.out"
	if $5 "$tmp/$1.out"; then
		ok "mutation $1: its cell kept the stale build ($(grep -E '^(value|flag)=' "$tmp/$1.out" | tr '\n' ' '))"
	else
		bad "mutation $1: the stale binary did not run ($(tr '\n' '|' <"$tmp/$1.out")); the cell cannot show the defect"
	fi
}
stale_edit() { printed "$1" 9; }
stale_flag() { flagged "$1" 0; }
stale_ahead() { printed "$1" 1; }
reused_build() { printed "$1" 1 && ! compiled "$1"; }
mutate no-dirty 's/^        if touched_on_runner(rel, path):$/        if False:/' runner_edit edit-m1 stale_edit
mutate content-only 's/^    return os\.stat(path)\.st_mtime_ns != entry\[1\].*/    return False/' runner_restore restore-m2 stale_edit
mutate no-deleted 's/^dirty |= set(known) - seen$/pass/' runner_delete delete-m3 stale_flag
mutate now-stamping 's/^stamp_new = now if floor is None else max(now, floor + SECOND)$/stamp_new = now/' runner_ahead ahead-m4 stale_ahead
mutate no-backstop 's/^if isinstance(last_sync, int) and now < last_sync:$/if False:/' runner_clock_back back-m5 reused_build

echo "vm-test-run sync selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
