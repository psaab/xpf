#!/usr/bin/env bash
# Struct-heterogeneity audit (#6937): list structs whose DISTINCT FIELD
# TYPE count is at or above AUDIT_STRUCT_FLOOR, sorted desc with category
# tags ([REFACTOR] at AUDIT_STRUCT_REFACTOR_FLOOR, [WATCH] below it).
#
# Complements scripts/refactoring-audit.sh, whose file-LOC measure cannot
# see field accretion: `Daemon` reached 255 fields inside a 1167-LOC file,
# legitimately under the [WATCH] floor. This struct census is advisory
# and incomplete: direct anonymous nested struct types collapse to one
# `struct{...}` token, so inner concerns may be undercounted. The separate
# touched-file LOC gate enforces file size only, not struct heterogeneity.
#
# The measurement lives in Go (pkg/refactoraudit) because it needs go/ast.
# A naive count of multi-line printer output inflates the census by treating
# nested rendering as multiple types. Exclusions and roots are PASSED IN
# from refactoring-audit-lib.sh rather than reimplemented, so that file
# stays the single source of truth.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
# shellcheck source=scripts/refactoring-audit-lib.sh
source scripts/refactoring-audit-lib.sh

exec go run ./pkg/refactoraudit/structaudit \
    -skip "$AUDIT_SKIP_RE" \
    -go-roots "$AUDIT_ROOTS_GO" \
    -rs-roots "$AUDIT_ROOTS_RS" \
    "$@"
