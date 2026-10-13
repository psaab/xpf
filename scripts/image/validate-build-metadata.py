#!/usr/bin/env python3
"""Fail closed on unsafe linker metadata passed to xpfd's `-X` flags (#12698)."""

import datetime
import os
import re
import sys


def main():
    # Environment-origin Make variables are already present in this process
    # environment. Missing values are Make's safe, locally-derived defaults;
    # validate those at the LDFLAGS expansion boundary via their fixed shape.
    version = os.environ.get("VERSION")
    commit = os.environ.get("COMMIT")
    build_time = os.environ.get("BUILD_TIME")
    if version is not None and version not in {"dev", "unknown"} and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._+~-]*", version):
        print("VERSION must match [A-Za-z0-9][A-Za-z0-9._+~-]*", file=sys.stderr)
        return 1
    if commit is not None and commit != "unknown" and not re.fullmatch(
            r"[0-9a-f]{7,40}", commit):
        print("COMMIT must be 'unknown' or 7-40 lowercase hex characters",
              file=sys.stderr)
        return 1
    if build_time is not None:
        try:
            parsed = datetime.datetime.strptime(build_time, "%Y-%m-%dT%H:%M:%SZ")
            if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != build_time:
                raise ValueError
        except ValueError:
            print("BUILD_TIME must be UTC RFC3339 YYYY-MM-DDTHH:MM:SSZ",
                  file=sys.stderr)
            return 1
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
