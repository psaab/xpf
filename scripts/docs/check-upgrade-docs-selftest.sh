#!/usr/bin/env bash
# Self-test for scripts/docs/check-upgrade-docs.sh (#9783).
#
# Hermetic: each row builds a fixture docs tree in a temp dir and runs the
# guard against it through DOCS_CHECK_ROOT. The row that matters most is the
# POSITIVE CONTROL. #9783 excluded the generated history archives from the
# phantom-symbol scan, and an exclusion that swallowed every match would turn
# the guard into a clean pass on any tree; only a live-doc hit that still
# fails can tell those apart.
set -u
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guard="$here/check-upgrade-docs.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail=0

# mkroot NAME: a fixture root holding a clean install-layout doc.
mkroot() {
	local r="$tmp/$1"
	mkdir -p "$r/docs"
	printf 'install layout\n' >"$r/docs/install-images.md"
	printf '%s\n' "$r"
}

# expect WANT_RC NAME ROOT
expect() {
	local want=$1 name=$2 root=$3 out rc
	out="$(DOCS_CHECK_ROOT="$root" bash "$guard" 2>&1)"
	rc=$?
	if [ "$rc" -eq "$want" ]; then
		echo "ok   $name (rc=$rc)"
	else
		echo "FAIL $name: want rc=$want, got rc=$rc"
		printf '%s\n' "$out" | sed 's/^/      /'
		fail=1
	fi
}

r=$(mkroot clean)
expect 0 "clean tree passes" "$r"

r=$(mkroot live)
echo 'edit manifest.Managed to add a binary' >"$r/docs/upgrade.md"
expect 1 "POSITIVE CONTROL: the symbol in a live doc fails" "$r"

r=$(mkroot history)
for d in issues log reviews; do
	mkdir -p "$r/docs/$d"
	echo 'removed the stale manifest.Managed reference' >"$r/docs/$d/history.md"
done
expect 0 "the symbol only under docs/issues, docs/log and docs/reviews passes" "$r"

r=$(mkroot nested)
mkdir -p "$r/docs/guide/log"
echo 'manifest.Managed' >"$r/docs/guide/log/steps.md"
expect 1 "a nested docs/guide/log/ is still scanned" "$r"

r=$(mkroot both)
mkdir -p "$r/docs/issues"
echo 'manifest.Managed' >"$r/docs/issues/history.md"
echo 'manifest.Managed' >>"$r/docs/install-images.md"
expect 1 "a live hit beside a history hit still fails" "$r"

r=$(mkroot noinstall)
rm "$r/docs/install-images.md"
expect 1 "fail-closed: a missing install doc is an error" "$r"

exit "$fail"
