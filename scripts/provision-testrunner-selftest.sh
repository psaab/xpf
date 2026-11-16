#!/usr/bin/env bash
# scripts/provision-testrunner-selftest.sh -- install_go in
# scripts/provision-testrunner.sh replaces a runner's Go toolchain only on a
# drained runner, and never leaves the toolchain missing (#19152, fold of
# the Codex review of b7e). Hermetic: the script's functions are sourced and
# run against a scratch tree, with the download, the lane probe and the final
# rename stubbed. Cells:
#   - same version, lane live: nothing to do, nothing touched;
#   - new version, lane live: refused (75), old toolchain intact;
#   - new version, idle: replaced, no stage or aside directory left behind;
#   - download is not the asked version: refused (2), old toolchain intact;
#   - the rename into place fails: the old toolchain is restored;
#   - no toolchain yet, lane live: installed (a fresh install replaces
#     nothing).
# Mutations: the drain check dropped (the live-lane cell replaces), the
# rollback dropped (the failed-rename cell leaves no toolchain).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/provision-testrunner.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/provision-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS: $*"; }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }

# go_tree <dir> <version>: a fake toolchain whose bin/go reports <version>.
go_tree() {
	mkdir -p "$1/bin"
	printf '#!/bin/sh\necho "go version go%s linux/amd64"\n' "$2" >"$1/bin/go"
	chmod +x "$1/bin/go"
}
# cell <script> <name> <installed-version|-> <want-version> [VAR=value...]:
# runs install_go in a subshell and prints "<rc> <version now at dir>
# <leftovers>".
cell() {
	local under=$1 name=$2 have=$3 want=$4
	shift 4
	local root="$tmp/$name"
	rm -rf "$root" && mkdir -p "$root"
	[[ "$have" != - ]] && go_tree "$root/go" "$have"
	(
		for kv in "$@"; do export "${kv?}"; done
		# shellcheck source=provision-testrunner.sh
		source "$under"
		set +e
		fetch_go() { go_tree "$2/go" "${FAKE_FETCH_VER:-$1}"; }
		lane_activity() { [[ -n "${FAKE_BUSY:-}" ]] && echo "runner process: $FAKE_BUSY"; return 0; }
		if [[ -n "${FAKE_SWITCH_FAIL:-}" ]]; then switch_into_place() { return 1; }; fi
		install_go "$want" "$root/go" 2>"$root.err"
		echo "$? $("$root/go/bin/go" version 2>/dev/null | awk '{print $3}') $(find "$root" -maxdepth 1 -name '.go-*' | wc -l)"
	)
}
expect() { # expect <label> <got> <want>
	if [[ "$2" == "$3" ]]; then ok "$1 ($2)"; else bad "$1: got [$2], want [$3]"; fi
}
run_cells() { # run_cells <script>: prints one result line per cell
	echo "same-busy $(cell "$1" same 1.24.9 1.24.9 FAKE_BUSY=cargo)"
	echo "new-busy $(cell "$1" busy 1.24.9 1.25.0 FAKE_BUSY=cargo)"
	echo "new-idle $(cell "$1" idle 1.24.9 1.25.0)"
	echo "bad-download $(cell "$1" baddl 1.24.9 1.25.0 FAKE_FETCH_VER=1.99.0)"
	echo "switch-fails $(cell "$1" swfail 1.24.9 1.25.0 FAKE_SWITCH_FAIL=1)"
	echo "fresh-busy $(cell "$1" fresh - 1.25.0 FAKE_BUSY=cargo)"
}
result() { sed -n "s/^$1 //p" "$2"; }

run_cells "$script" >"$tmp/real.txt"
expect "same version with a live lane: nothing to do" "$(result same-busy "$tmp/real.txt")" "0 go1.24.9 0"
expect "new version with a live lane: refused, old toolchain intact" "$(result new-busy "$tmp/real.txt")" "75 go1.24.9 0"
expect "new version on an idle runner: replaced, nothing left behind" "$(result new-idle "$tmp/real.txt")" "0 go1.25.0 0"
expect "download is not the asked version: refused, old toolchain intact" "$(result bad-download "$tmp/real.txt")" "2 go1.24.9 0"
expect "rename into place fails: the old toolchain is restored" "$(result switch-fails "$tmp/real.txt")" "2 go1.24.9 0"
expect "fresh install with a live lane: installed (replaces nothing)" "$(result fresh-busy "$tmp/real.txt")" "0 go1.25.0 0"
grep -q 'refusing to replace .* while a lane is live' "$tmp/busy.err" && ok "the refusal names the live lane" || bad "the refusal message: $(cat "$tmp/busy.err")"

# mutant <name> <sed program>: a copy of the script with one change.
mutant() {
	sed "$2" "$script" >"$tmp/$1.sh"
	if cmp -s "$script" "$tmp/$1.sh"; then bad "mutation $1: anchor not found"; return 1; fi
}
# shellcheck disable=SC2016 # a sed program: the $ is literal
if mutant no-drain 's/^\t\tbusy=$(lane_activity)$/\t\tbusy=/'; then
	run_cells "$tmp/no-drain.sh" >"$tmp/m1.txt"
	[[ "$(result new-busy "$tmp/m1.txt")" != "75 go1.24.9 0" ]] && ok "mutation no-drain: the live-lane cell replaces the toolchain" || bad "mutation no-drain: the live-lane cell still refuses"
fi
# shellcheck disable=SC2016 # a sed program: the $ is literal
if mutant no-rollback 's/^\t\t\tmv -T "$aside" "$dir"$/\t\t\t:/'; then
	run_cells "$tmp/no-rollback.sh" >"$tmp/m2.txt"
	[[ "$(result switch-fails "$tmp/m2.txt")" != "2 go1.24.9 0" ]] && ok "mutation no-rollback: the failed-rename cell is left without its toolchain" || bad "mutation no-rollback: the failed-rename cell still restores"
fi

echo "provision-testrunner selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
