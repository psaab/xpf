#!/usr/bin/env bash
# scripts/provision-testrunner-selftest.sh -- the Go toolchain install in
# scripts/provision-testrunner.sh never replaces a toolchain in place, never
# leaves a published path missing, and never deletes a toolchain (#19152; folds
# of the Codex reviews of b7e, b7f and b7g: the GC was removed). Hermetic: the
# script's functions are sourced and run against a scratch tree, with the
# download stubbed. Cells:
#   - fresh install: the versioned dir is created and the links resolve to it;
#   - upgrade: a new versioned dir, the links flip to it, the old tree stays;
#   - the same version again: nothing changes, nothing is left behind;
#   - a download that is not the asked version: nothing installed or flipped;
#   - a versioned dir with the wrong content: refused, untouched;
#   - a pre-versioned real /usr/local/go directory: left alone by publish;
#   - the rename that publishes a link fails: the old link still resolves;
#   - the script carries no deletion of a toolchain path at all.
# Mutations: publish made non-atomic (unlink, then link), an install that
# deletes the other versions.
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
	printf '#!/bin/sh\nexit 0\n' >"$1/bin/gofmt"
	chmod +x "$1/bin/go" "$1/bin/gofmt"
}
ver_of() { "$1" version 2>/dev/null | awk '{print $3}'; }

# scenario <script> <name> <bash snippet>: a fresh scratch root R with
# R/usr/local/bin and R/usr/lib, the functions sourced, the stubs installed,
# and the snippet run; prints whatever the snippet echoes.
scenario() {
	local under=$1 name=$2 body=$3
	local R="$tmp/$name"
	rm -rf "$R" && mkdir -p "$R/usr/local/bin" "$R/usr/lib"
	(
		# shellcheck source=provision-testrunner.sh
		source "$under"
		set +e
		fetch_go() { go_tree "$2/go" "${FAKE_FETCH_VER:-$1}"; }
		publish_build() { # publish_build <version>
			publish_link "$R/usr/local/go-$1/bin/go" "$R/usr/local/bin/go"
			publish_link "$R/usr/local/go-$1" "$R/usr/local/go"
		}
		eval "$body"
	) 2>"$tmp/$name.err"
}
expect() { if [[ "$2" == "$3" ]]; then ok "$1 ($2)"; else bad "$1: got [$2], want [$3]"; fi; }

run_cells() { # run_cells <script>: one line per cell
	echo "fresh $(scenario "$1" fresh 'install_go_version 1.24.9 "$R/usr/local/go-1.24.9"; publish_build 1.24.9; echo "$(ver_of "$R/usr/local/bin/go") $(ver_of "$R/usr/local/go/bin/go")"')"
	echo "upgrade $(scenario "$1" upgrade 'install_go_version 1.24.9 "$R/usr/local/go-1.24.9"; publish_build 1.24.9; install_go_version 1.25.0 "$R/usr/local/go-1.25.0"; publish_build 1.25.0; echo "$(ver_of "$R/usr/local/bin/go") old=$(ver_of "$R/usr/local/go-1.24.9/bin/go")"')"
	echo "again $(scenario "$1" again 'install_go_version 1.24.9 "$R/usr/local/go-1.24.9"; install_go_version 1.24.9 "$R/usr/local/go-1.24.9"; echo "rc=$? $(ls -A "$R/usr/local" | grep -c "^\.go-")"')"
	echo "baddl $(scenario "$1" baddl 'install_go_version 1.24.9 "$R/usr/local/go-1.24.9"; publish_build 1.24.9; FAKE_FETCH_VER=1.99.0 install_go_version 1.25.0 "$R/usr/local/go-1.25.0"; echo "rc=$? $([[ -e "$R/usr/local/go-1.25.0" ]] && echo made || echo none) $(ver_of "$R/usr/local/bin/go")"')"
	echo "wrongdir $(scenario "$1" wrongdir 'go_tree "$R/usr/local/go-1.25.0" 1.99.0; install_go_version 1.25.0 "$R/usr/local/go-1.25.0"; echo "rc=$? $(ver_of "$R/usr/local/go-1.25.0/bin/go")"')"
	echo "legacy $(scenario "$1" legacy 'go_tree "$R/usr/local/go" 1.24.9; install_go_version 1.25.0 "$R/usr/local/go-1.25.0"; publish_build 1.25.0; echo "$([[ -d "$R/usr/local/go" && ! -L "$R/usr/local/go" ]] && echo dir-kept || echo replaced) $(ver_of "$R/usr/local/bin/go")"')"
	echo "renamefail $(scenario "$1" renamefail 'install_go_version 1.24.9 "$R/usr/local/go-1.24.9"; publish_build 1.24.9; install_go_version 1.25.0 "$R/usr/local/go-1.25.0"; rename_into_place() { return 1; }; publish_build 1.25.0; echo "rc=$? $(ver_of "$R/usr/local/bin/go")"')"
}
result() { sed -n "s/^$1 //p" "$2"; }

run_cells "$script" >"$tmp/real.txt"
expect "fresh install: the links resolve to the new versioned dir" "$(result fresh "$tmp/real.txt")" "go1.24.9 go1.24.9"
expect "upgrade: the links flip to the new version, the old tree stays" "$(result upgrade "$tmp/real.txt")" "go1.25.0 old=go1.24.9"
expect "the same version again: nothing to do, nothing left behind" "$(result again "$tmp/real.txt")" "rc=0 0"
expect "a wrong download: nothing installed, the link unchanged" "$(result baddl "$tmp/real.txt")" "rc=2 none go1.24.9"
expect "a versioned dir with the wrong content: refused, untouched" "$(result wrongdir "$tmp/real.txt")" "rc=2 go1.99.0"
expect "a pre-versioned /usr/local/go directory: left alone" "$(result legacy "$tmp/real.txt")" "dir-kept go1.25.0"
expect "the publishing rename fails: the old link still resolves" "$(result renamefail "$tmp/real.txt")" "rc=2 go1.24.9"
# No GC (fold of Codex on b7g): nothing in the script may delete a toolchain
# path. The only rm -rf left is the failed-download staging cleanup.
rmlines=$(grep -nE 'rm -r|rm -fr|rmdir' "$script" | grep -v '^#' | grep -vE 'rm -rf "\$stage"$|rmdir "\$stage"$|rm -f "\$tmp"' || true)
if [[ -z "$rmlines" ]] && ! grep -q -- '--gc-toolchains' "$script"; then
	ok "no toolchain deletion: the script has no GC and removes only its own staging"
else
	bad "a deletion is back in the provision script: $rmlines"
fi

# mutant <name> <sed program>: a copy of the script with one change.
mutant() {
	sed "$2" "$script" >"$tmp/$1.sh"
	if cmp -s "$script" "$tmp/$1.sh"; then bad "mutation $1: anchor not found"; return 1; fi
}
# shellcheck disable=SC2016 # sed programs: the $ is literal
if mutant non-atomic-publish 's/^\tln -sfn "$target" "$tmp"$/\trm -f "$link"; ln -sfn "$target" "$tmp"/'; then
	run_cells "$tmp/non-atomic-publish.sh" >"$tmp/m1.txt"
	[[ "$(result renamefail "$tmp/m1.txt")" != "rc=2 go1.24.9" ]] && ok "mutation non-atomic-publish: a failed rename leaves the link missing" || bad "mutation non-atomic-publish: the rename-failure cell still passes"
fi
# shellcheck disable=SC2016
if mutant install-deletes-old 's|^\tmv -T "$stage/go" "$dir"$|\trm -rf "$(dirname "$dir")"/go-[0-9]*; mv -T "$stage/go" "$dir"|'; then
	run_cells "$tmp/install-deletes-old.sh" >"$tmp/m2.txt"
	[[ "$(result upgrade "$tmp/m2.txt")" != "go1.25.0 old=go1.24.9" ]] && ok "mutation install-deletes-old: the upgrade cell loses the old tree" || bad "mutation install-deletes-old: the upgrade cell still passes"
fi
echo "provision-testrunner selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
