#!/usr/bin/env bash
# scripts/vm-test-run-sync-selftest.sh -- #19134: a reused vm-test-run.sh lane
# (`--name`) must never re-test a previous cargo binary, and the clean that
# prevents it must never reach outside the lane.
#
# cargo calls a crate fresh when no source file is newer than its artefacts,
# and the lane's target dir outlives every sync. vm-test-run.sh keeps that dir
# only when nothing is in doubt (same tree identity, no runner-side changes, a
# current ledger, no scan error) and otherwise deletes it, through directory
# fds, inside a lane it has checked is a plain directory with no mount under
# it. Hermetic apart from cargo: a mock `incus` on PATH runs the runner side
# locally (paths under /work/ rewritten into a sandbox), and each "tree" is a
# scratch git worktree holding a small crate that prints value=<n>.
#
# Cells (each stale-binary case must rebuild and print the NEW value):
#   - control: the trap is real on this toolchain -- an older-mtime source
#     over a kept build runs the old binary;
#   - fresh lane, then an unchanged re-sync that must KEEP the build (no
#     recompile), so incremental builds survive;
#   - older tree (the issue): B, older than A's build, into A's lane;
#   - runner-side edit; restored after build (edit, build, original bytes
#     back); deleted after build (a build script probing a deleted file);
#   - build-script-only partial build: a build script compiled, then failed
#     at run time, then the tree changed the build script;
#   - artefacts ahead of the clock (a clock stepped back after the build);
#   - unreadable deps: target/debug/deps mode 000 must still be cleaned;
#   - unbuilt middle sync; no ledger; an older-format ledger;
#   - a lane that is a symlink to another lane (/work/alias -> /work/other)
#     must be refused, and a sentinel in the other lane's target survives;
#   - a bind mount under the lane must be refused, and a sentinel in the
#     mounted directory survives (needs `unshare -Urm`; SKIP without it).
# Mutations, each KILLED only when its cell observably runs the stale binary
# or loses its sentinel: no tree-identity check (older tree runs value=1); no
# runner-side-change check (restored after build runs value=9); following a
# symlinked lane (the alias sentinel is deleted); no mount check (the
# bind-mount sentinel is deleted).
# Needs cargo; exits 77 (SKIP) without it.
# The cell and mutant checks are single-quoted on purpose: they are eval'd
# after the cell has run.
# shellcheck disable=SC2016
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script="$here/vm-test-run.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/vm-test-run-sync-selftest.XXXXXX")
trap 'chmod -R u+rwx "$tmp" 2>/dev/null || true; rm -rf "$tmp"' EXIT

if ! command -v cargo >/dev/null 2>&1; then
	echo "SKIP: cargo not installed"
	exit 77
fi

pass=0
fail=0
skip=0
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

# new_tree <dir> <mtime>: an empty git worktree with a crate manifest.
new_tree() {
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
}
# finish_tree <dir> <mtime>: lockfile, then every file stamped <mtime>.
finish_tree() {
	(cd "$1" && cargo generate-lockfile --offline >/dev/null 2>&1)
	find "$1" -path "$1/.git" -prune -o -type f -exec touch -d "$2" {} +
}
# make_tree <dir> <value> <mtime>: prints value=<value>.
make_tree() {
	new_tree "$1"
	printf 'const VALUE: u32 = %s;\nfn main() {\n    println!("value={}", VALUE);\n}\n' "$2" >"$1/src/main.rs"
	finish_tree "$1" "$3"
}
# make_probe_tree <dir> <mtime>: a build script (build.rs, found by cargo on
# its own) bakes in whether flag.txt exists (flag=1/0) and asks cargo to
# re-run it when flag.txt changes.
make_probe_tree() {
	new_tree "$1"
	cat >"$1/build.rs" <<'RS'
fn main() {
    println!("cargo:rerun-if-changed=flag.txt");
    let flag = if std::path::Path::new("flag.txt").exists() { 1 } else { 0 };
    println!("cargo:rustc-env=PROBE_FLAG={flag}");
}
RS
	printf 'fn main() {\n    println!("flag={}", env!("PROBE_FLAG"));\n}\n' >"$1/src/main.rs"
	echo on >"$1/flag.txt"
	finish_tree "$1" "$2"
}
# make_script_tree <dir> <value> <mtime>: the VALUE comes from the build
# script, which fails while PROBE_FAIL is set.
make_script_tree() {
	new_tree "$1"
	cat >"$1/build.rs" <<RS
fn main() {
    if std::env::var_os("PROBE_FAIL").is_some() {
        panic!("build script failing as asked (#19134 selftest)");
    }
    println!("cargo:rustc-env=PROBE_VALUE=$2");
}
RS
	printf 'fn main() {\n    println!("value={}", env!("PROBE_VALUE"));\n}\n' >"$1/src/main.rs"
	finish_tree "$1" "$3"
}
make_tree "$tmp/A" 1 "2020-06-01 00:00:00"
make_tree "$tmp/B" 2 "2001-01-01 00:00:00"
make_tree "$tmp/C" 2 "1999-01-01 00:00:00"
make_probe_tree "$tmp/D" "2010-01-01 00:00:00"
make_script_tree "$tmp/E1" 1 "2015-01-01 00:00:00"
make_script_tree "$tmp/E2" 2 "2005-01-01 00:00:00"

# lane <script> <tree> <name> <out> <command>: run the command on the mock
# runner from <tree>, syncing it into lane <name>; the status goes to <out>.rc.
lane() {
	local rc=0
	(cd "$2" && PATH="$tmp/bin:$PATH" MOCK_ROOT="$tmp" CARGO_NET_OFFLINE=true \
		bash "$1" --runner mock:runner --name "$3" -- "$5") >"$4" 2>&1 || rc=$?
	echo "$rc" >"$4.rc"
}
run_cmd='cargo run --offline 2>&1'
compiled() { grep -q 'Compiling stalefix19134' "$1"; }
printed() { grep -qx "value=$2" "$1"; }
flagged() { grep -qx "flag=$2" "$1"; }
cleaned() { grep -q "cleaned the lane's target dir: .*$2" "$1"; }
kept() { grep -q "kept the lane's build" "$1"; }
refused() { [[ "$(cat "$1.rc")" == 2 ]] && grep -q 'refusing' "$1"; }
# show <out>: the lines that decide a cell (values, sentinels, cargo's verdict,
# the lane decision), compactly.
show() {
	{ grep -E '^(value|flag)=|^sentinel-|Compiling|Finished|^vm-test-run: (cleaned|kept|refusing)|^error' "$1" || true; } |
		sed -E 's/ v0\.0\.0 \(.*//; s/ \[unoptimized.*in / in /' | tail -n 6 | tr '\n' '|'
}

# control: the trap itself, without vm-test-run.sh.
cp -a "$tmp/A" "$tmp/ctl"
(cd "$tmp/ctl" && CARGO_TARGET_DIR="$tmp/ctl-target" cargo run --offline >/dev/null 2>&1)
cp -a "$tmp/B/src/main.rs" "$tmp/ctl/src/main.rs" # cp -a keeps B's older mtime
(cd "$tmp/ctl" && CARGO_TARGET_DIR="$tmp/ctl-target" cargo run --offline) >"$tmp/ctl.out" 2>&1 || true
if printed "$tmp/ctl.out" 1; then
	ok "control: with A's build kept, an older-mtime B runs A's binary (value=1): the trap is real"
else
	bad "control: cargo did not serve the stale binary; the cells below prove nothing ($(show "$tmp/ctl.out"))"
fi

# fresh lane, then the unchanged re-sync.
lane "$script" "$tmp/A" one "$tmp/a1.out" "$run_cmd"
if compiled "$tmp/a1.out" && printed "$tmp/a1.out" 1 && cleaned "$tmp/a1.out" "no ledger"; then
	ok "fresh lane: A compiles and prints value=1"
else
	bad "fresh lane: $(show "$tmp/a1.out")"
fi
lane "$script" "$tmp/A" one "$tmp/a2.out" "$run_cmd"
if kept "$tmp/a2.out" && ! compiled "$tmp/a2.out" && printed "$tmp/a2.out" 1; then
	ok "unchanged re-sync: the build is kept, nothing recompiles, value=1"
else
	bad "unchanged re-sync: $(show "$tmp/a2.out")"
fi

# Each cell function: <script> <lane> <out>; the final run's output is <out>.
older() {
	lane "$1" "$tmp/A" "$2" "$3.prep" "$run_cmd"
	lane "$1" "$tmp/B" "$2" "$3" "$run_cmd"
}
runner_edit() {
	lane "$1" "$tmp/B" "$2" "$3.prep" "$run_cmd"
	lane "$1" "$tmp/B" "$2" "$3.edit" "sed -i 's/= 2;/= 9;/' src/main.rs && $run_cmd"
	lane "$1" "$tmp/B" "$2" "$3" "$run_cmd"
}
runner_restore() {
	local sum
	# The tree's bytes by checksum, not path: the mock rewrites /work/ paths.
	sum=$(sha256sum <"$tmp/B/src/main.rs" | cut -c1-64)
	lane "$1" "$tmp/B" "$2" "$3.prep" "$run_cmd"
	lane "$1" "$tmp/B" "$2" "$3.edit" "sed -i 's/= 2;/= 9;/' src/main.rs && $run_cmd && sed -i 's/= 9;/= 2;/' src/main.rs && [ \"\$(sha256sum <src/main.rs | cut -c1-64)\" = $sum ] && echo restored-bytes"
	lane "$1" "$tmp/B" "$2" "$3" "$run_cmd"
}
runner_delete() {
	lane "$1" "$tmp/D" "$2" "$3.prep" "$run_cmd"
	lane "$1" "$tmp/D" "$2" "$3.del" "rm flag.txt && $run_cmd"
	lane "$1" "$tmp/D" "$2" "$3" "$run_cmd"
}
script_partial() {
	lane "$1" "$tmp/E1" "$2" "$3.fail" "PROBE_FAIL=1 $run_cmd"
	lane "$1" "$tmp/E2" "$2" "$3" "$run_cmd"
}
ahead() {
	lane "$1" "$tmp/A" "$2" "$3.prep" "$run_cmd"
	find "$tmp/work/$2/target" -exec touch -h -d "@$(($(date +%s) + 86400))" {} +
	lane "$1" "$tmp/B" "$2" "$3" "$run_cmd"
}
unreadable() {
	lane "$1" "$tmp/A" "$2" "$3.prep" "$run_cmd"
	chmod 000 "$tmp/work/$2/target/debug/deps"
	lane "$1" "$tmp/B" "$2" "$3" "$run_cmd"
}
middle() {
	lane "$1" "$tmp/A" "$2" "$3.prep" "$run_cmd"
	lane "$1" "$tmp/B" "$2" "$3.mid" "true"
	lane "$1" "$tmp/C" "$2" "$3" "$run_cmd"
}
no_ledger() {
	lane "$1" "$tmp/A" "$2" "$3.prep" "$run_cmd"
	rm -f "$tmp/work/$2/.xpf-src-ledger.json"
	lane "$1" "$tmp/A" "$2" "$3" "$run_cmd"
}
old_ledger() {
	lane "$1" "$tmp/A" "$2" "$3.prep" "$run_cmd"
	printf '{"v": 2, "files": {}, "last_sync_ns": 0}' >"$tmp/work/$2/.xpf-src-ledger.json"
	lane "$1" "$tmp/A" "$2" "$3" "$run_cmd"
}
# alias: lane <name>-other built with a sentinel in its target, and
# <name>-alias a symlink to it; syncing B through the alias must be refused.
alias_lane() {
	lane "$1" "$tmp/A" "$2-other" "$3.prep" "$run_cmd"
	echo keep >"$tmp/work/$2-other/target/sentinel-19134"
	ln -sfn "$2-other" "$tmp/work/$2-alias"
	lane "$1" "$tmp/B" "$2-alias" "$3" "$run_cmd"
	[[ -f "$tmp/work/$2-other/target/sentinel-19134" ]] && echo sentinel-present >>"$3" || echo sentinel-gone >>"$3"
}
# bind: a directory outside the lane, holding a sentinel, bind-mounted inside
# the lane's target; syncing B must be refused. Runs in a private user+mount
# namespace, so the mount never leaves this cell.
bind_lane() {
	lane "$1" "$tmp/A" "$2" "$3.prep" "$run_cmd"
	mkdir -p "$tmp/outside-$2" "$tmp/work/$2/target/mnt"
	echo keep >"$tmp/outside-$2/sentinel-19134"
	unshare -Urm bash -c 'mount --bind "$1" "$2" && cd "$3" &&
		PATH="$4/bin:$PATH" MOCK_ROOT="$4" CARGO_NET_OFFLINE=true bash "$5" --runner mock:runner --name "$6" -- "$7"' \
		_ "$tmp/outside-$2" "$tmp/work/$2/target/mnt" "$tmp/B" "$tmp" "$1" "$2" "$run_cmd" >"$3" 2>&1 && echo 0 >"$3.rc" || echo $? >"$3.rc"
	[[ -f "$tmp/outside-$2/sentinel-19134" ]] && echo sentinel-present >>"$3" || echo sentinel-gone >>"$3"
}

# cell <description> <function> <lane> <check...>
cell() {
	local what=$1 fn=$2 name=$3
	shift 3
	"$fn" "$script" "$name" "$tmp/$name.out"
	if "$@"; then ok "$what"; else bad "$what: $(show "$tmp/$name.out")"; fi
}
rebuilt() { cleaned "$1" "$2" && compiled "$1" && printed "$1" "$3"; }
cell "older tree: B (older than A's build) into A's lane rebuilds (value=2)" older older \
	rebuilt "$tmp/older.out" "the synced tree changed" 2
cell "runner-side edit: a run that built value=9 on the runner is followed by a rebuild (value=2)" runner_edit edit \
	eval 'printed "$tmp/edit.out.edit" 9 && rebuilt "$tmp/edit.out" "the last run changed" 2'
cell "restored after build: original bytes written back after building value=9 still rebuild (value=2)" runner_restore restore \
	eval 'printed "$tmp/restore.out.edit" 9 && grep -qx restored-bytes "$tmp/restore.out.edit" && rebuilt "$tmp/restore.out" "the last run changed" 2'
cell "deleted after build: a run that built without flag.txt is followed by a rebuild (flag=1)" runner_delete delete \
	eval 'flagged "$tmp/delete.out.del" 0 && cleaned "$tmp/delete.out" "removed 1" && flagged "$tmp/delete.out" 1'
cell "build-script-only partial build: a changed build script after a failed run rebuilds (value=2)" script_partial partial \
	eval 'grep -q "failing as asked" "$tmp/partial.out.fail" && rebuilt "$tmp/partial.out" "the synced tree changed" 2'
cell "artefacts ahead of the clock: a changed tree still rebuilds (value=2)" ahead ahead \
	rebuilt "$tmp/ahead.out" "the synced tree changed" 2
cell "unreadable deps: a mode-000 target/debug/deps is still cleaned and the tree rebuilds (value=2)" unreadable unread \
	rebuilt "$tmp/unread.out" "the synced tree changed" 2
cell "unbuilt middle sync: C after an unbuilt B rebuilds (value=2)" middle middle \
	eval 'compiled "$tmp/middle.out" && printed "$tmp/middle.out" 2'
cell "no ledger: a lane whose ledger is gone is cleaned (value=1, recompiled)" no_ledger noledger \
	rebuilt "$tmp/noledger.out" "no ledger" 1
cell "older-format ledger: a format-2 ledger counts as none (value=1, recompiled)" old_ledger oldledger \
	rebuilt "$tmp/oldledger.out" "older format" 1
cell "symlinked lane: /work/x-alias -> /work/x-other is refused and the other lane's sentinel survives" alias_lane x \
	eval 'refused "$tmp/x.out" && grep -qx sentinel-present "$tmp/x.out"'
have_userns=1
if ! unshare -Urm true 2>/dev/null; then
	have_userns=0
	skip=$((skip + 1))
	echo "SKIP: bind mount under the lane: unshare -Urm is not available here"
else
	cell "bind mount under the lane: refused, and the mounted directory's sentinel survives" bind_lane bm \
		eval 'refused "$tmp/bm.out" && grep -qx sentinel-present "$tmp/bm.out"'
fi

# mutate <name> <sed expr> <cell function> <lane> <check>: KILLED only when
# the mutant's cell observably runs the stale binary or loses its sentinel.
mutate() {
	sed "$2" "$script" >"$tmp/$1.sh"
	if cmp -s "$script" "$tmp/$1.sh"; then
		bad "mutation $1: the anchor was not found"
		return
	fi
	"$3" "$tmp/$1.sh" "$4" "$tmp/$1.out"
	if eval "$5"; then
		ok "mutation $1: its cell showed the defect ($(grep -E '^(value|flag)=|^sentinel-' "$tmp/$1.out" | tr '\n' ' '))"
	else
		bad "mutation $1: the defect did not show ($(show "$tmp/$1.out")); the cell cannot catch it"
	fi
}
mutate no-identity 's/^        if ledger_tree != identity(new):$/        if False:/' older m1 'printed "$tmp/no-identity.out" 1'
mutate no-runner-check 's/^            if changed or gone:$/            if False:/' runner_restore m2 'printed "$tmp/no-runner-check.out" 9'
mutate follow-symlink 's/^    return os.open(name, DIR_FLAGS | os.O_NOFOLLOW, dir_fd=pfd)$/    return os.open(name, DIR_FLAGS, dir_fd=pfd)/' alias_lane m3 'grep -qx sentinel-gone "$tmp/follow-symlink.out"'
if [[ "$have_userns" -eq 1 ]]; then
	mutate no-mount-check 's/^    return found$/    return []/' bind_lane m4 'grep -qx sentinel-gone "$tmp/no-mount-check.out"'
fi

echo "vm-test-run sync selftest: ${pass} passed, ${fail} failed, ${skip} skipped"
[[ "$fail" -eq 0 ]]
