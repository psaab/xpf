#!/usr/bin/env python3
"""Test-only import loader for script tests (#16194, Stage A).

``load_subject(name, path)`` replaces the ``spec_from_file_location``
boilerplate repeated across the script tests.  Production CLI files
stay hyphenated plain files invoked by their original paths (Makefile
and doc contracts); nothing here is a package, a shim, or an importable
production module, and no ``__file__``-derived root moves.

Semantics — identical to the dominant pre-helper block, plus the
registration the dataclass subjects need:

* the module is registered in ``sys.modules`` under ``name`` BEFORE it
  executes, so ``dataclasses`` (which resolves string annotations
  through ``sys.modules[cls.__module__]``) and any self-import in the
  subject find the executing module, and identity is preserved:
  ``sys.modules[name] is <returned module>``;
* if execution raises, the registration this call installed is
  removed, any prior ``sys.modules`` entry under the same name is
  restored, and the exception propagates unchanged (fail closed: a
  later ``import name`` must not find a broken module);
* a missing file or unloadable path raises instead of returning a
  loader-less module.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def load_subject(name: str, path: str | Path) -> ModuleType:
    """Load the file at ``path`` as module ``name`` and return it.

    Registers the module in ``sys.modules`` before executing it and
    removes the registration again if execution fails.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {name!r} from {path!r}")
    if not Path(path).is_file():
        raise ImportError(f"cannot load {name!r} from {path!r}: no such file")
    mod = importlib.util.module_from_spec(spec)
    prior = sys.modules.get(name)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        if sys.modules.get(name) is mod:
            if prior is None:
                del sys.modules[name]
            else:
                sys.modules[name] = prior
        raise
    return mod
