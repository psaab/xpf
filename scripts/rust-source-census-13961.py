#!/usr/bin/env python3
"""Fail when a Rust source file under a source root is unreachable from its crate roots."""
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
files = sorted(root.rglob("*.rs"))
rel = {p.relative_to(root).as_posix(): p for p in files}

def blank(text):
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            depth = 1
            j = i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif c == '"' or (c == "r" and i + 1 < n and text[i + 1] in '"#'):
            if c == "r":
                k = i + 1
                while k < n and text[k] == "#":
                    k += 1
                if k < n and text[k] == '"':
                    hashes = k - i - 1
                    end = text.find('"' + "#" * hashes, k + 1)
                    end = n if end < 0 else end + 1 + hashes
                    out.append("".join("\n" if ch == "\n" else " " for ch in text[i:end]))
                    i = end
                    continue
                out.append(c)
                i += 1
                continue
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif c == "'":
            match = re.match(r"'(\\.|[^\\'])'", text[i:i + 5])
            if match:
                out.append(" " * match.end())
                i += match.end()
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)

module = re.compile(r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*(;|{)")
path_attr = re.compile(r'#\[\s*path\s*=\s*"([^"]*)"')
include = re.compile(r'\binclude!\s*\(')

def normalise(path):
    parts = []
    for part in path.replace("\\", "/").split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return "/".join(parts)

edges = {}
for name, path in rel.items():
    text = path.read_text(errors="replace")
    code = blank(text)
    owner = str(Path(name).parent) if path.name == "mod.rs" else ("." if path.name in ("main.rs", "lib.rs") else name[:-3])
    targets = set()
    for found in include.finditer(code):
        string = re.match(r'\s*include!\s*\(\s*"([^"]*)"', text[found.start():])
        if string:
            targets.add(normalise((Path(name).parent / string.group(1)).as_posix()))
    pending = None
    brace_depth = 0
    inline_modules = []
    for original, source in zip(text.splitlines(), code.splitlines()):
        while inline_modules and brace_depth < inline_modules[-1][0]:
            inline_modules.pop()
        current_owner = Path(owner).joinpath(*(name for _, name in inline_modules))
        attribute = path_attr.search(original)
        if attribute and source.lstrip().startswith("#["):
            pending = attribute.group(1)
        declaration = module.search(source)
        if declaration:
            mod_name, terminator = declaration.groups()
            if terminator == ";":
                if pending is not None:
                    targets.add(normalise((Path(name).parent / pending).as_posix()))
                else:
                    targets.add(normalise((current_owner / f"{mod_name}.rs").as_posix()))
                    targets.add(normalise((current_owner / mod_name / "mod.rs").as_posix()))
            pending = None
            if terminator == "{":
                inline_modules.append((brace_depth + source.count("{") - source.count("}"), mod_name))
        elif source.strip() and not source.lstrip().startswith("#["):
            pending = None
        brace_depth += source.count("{") - source.count("}")
    edges[name] = targets

roots = ["main.rs"] + [p.relative_to(root).as_posix() for p in (root / "bin").glob("*.rs")]
seen = set()
stack = [name for name in roots if name in rel]
while stack:
    current = stack.pop()
    if current in seen:
        continue
    seen.add(current)
    stack.extend(target for target in edges.get(current, ()) if target in rel and target not in seen)
unreachable = sorted(set(rel) - seen)
if unreachable:
    print("Rust source files unreachable from crate roots:", file=sys.stderr)
    print("\n".join(f"  {name}" for name in unreachable), file=sys.stderr)
    sys.exit(1)
print(f"Rust source reachability: {len(seen)} files reachable from {len(roots)} crate roots")
