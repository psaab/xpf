#!/usr/bin/env python3
"""Fail when a Rust source file under a source root is unreachable from its crate roots."""
import re
import sys
import tempfile
from pathlib import Path

MODULE = re.compile(r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*(;|{)")
PATH_ATTR = re.compile(r'path\s*=\s*"([^"]*)"')
INCLUDE = re.compile(r"\binclude!\s*\(")


def blank(text):
    """Blank comments, strings and chars while preserving offsets and newlines."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(" " * (end - i))
            i = end
        elif text.startswith("/*", i):
            depth = 1
            end = i + 2
            while end < n and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            out.append("".join("\n" if c == "\n" else " " for c in text[i:end]))
            i = end
        elif text[i] == "r" and i + 1 < n and text[i + 1] in '"#':
            end = i + 1
            while end < n and text[end] == "#":
                end += 1
            if end < n and text[end] == '"':
                hashes = end - i - 1
                close = text.find('"' + "#" * hashes, end + 1)
                end = n if close < 0 else close + 1 + hashes
                out.append("".join("\n" if c == "\n" else " " for c in text[i:end]))
                i = end
            else:
                out.append(text[i])
                i += 1
        elif text[i] == '"':
            end = i + 1
            while end < n:
                if text[end] == "\\":
                    end += 2
                    continue
                if text[end] == '"':
                    end += 1
                    break
                end += 1
            out.append("".join("\n" if c == "\n" else " " for c in text[i:end]))
            i = end
        elif text[i] == "'":
            char = re.match(r"'(\\.|[^\\'])'", text[i:i + 5])
            if char:
                out.append(" " * char.end())
                i += char.end()
            else:  # lifetime apostrophe
                out.append(text[i])
                i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def normalise(path):
    parts = []
    for part in Path(path).as_posix().split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return "/".join(parts)


def source_graph(root):
    root = Path(root).resolve()
    files = sorted(root.rglob("*.rs"))
    rel = {p.relative_to(root).as_posix(): p for p in files}
    edges = {}
    for source_name, path in rel.items():
        text = path.read_text(errors="replace")
        code = blank(text)
        owner = Path(source_name).parent if path.name == "mod.rs" else (Path(".") if path.name in ("main.rs", "lib.rs") else Path(source_name).with_suffix(""))
        targets = set()

        # Include paths are read from original source at lexer-confirmed macro
        # locations: the blanked copy deliberately hides their string literals.
        for found in INCLUDE.finditer(code):
            literal = re.match(r'\s*include!\s*\(\s*"([^"]*)"', text[found.start():])
            if literal:
                targets.add(normalise(Path(source_name).parent / literal.group(1)))

        pending_path = None
        brace_depth = 0
        inline_modules = []  # (brace depth of module body, identifier)
        for original, masked in zip(text.splitlines(), code.splitlines()):
            while inline_modules and brace_depth < inline_modules[-1][0]:
                inline_modules.pop()
            current_owner = owner.joinpath(*(name for _, name in inline_modules))
            path_match = PATH_ATTR.search(original)
            if path_match and masked.lstrip().startswith("#["):
                pending_path = path_match.group(1)

            declaration = MODULE.search(masked)
            if declaration:
                mod_name, terminator = declaration.groups()
                if terminator == ";":
                    if pending_path is not None:
                        base = current_owner if inline_modules else Path(source_name).parent
                        targets.add(normalise(base / pending_path))
                    else:
                        targets.add(normalise(current_owner / f"{mod_name}.rs"))
                        targets.add(normalise(current_owner / mod_name / "mod.rs"))
                    pending_path = None
                else:
                    # Record the depth at this specific opening brace, not the
                    # end-of-line depth (which may include nested function
                    # bodies or closes on the same line).
                    opening = masked.find("{", declaration.start(), declaration.end())
                    module_depth = brace_depth + masked[:opening].count("{") - masked[:opening].count("}") + 1
                    inline_modules.append((module_depth, mod_name))
                    pending_path = None
            elif masked.strip() and not masked.lstrip().startswith("#["):
                pending_path = None

            brace_depth += masked.count("{") - masked.count("}")
        edges[source_name] = targets

    roots = ["main.rs"] + [p.relative_to(root).as_posix() for p in (root / "bin").glob("*.rs")]
    seen = set()
    stack = [name for name in roots if name in rel]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        stack.extend(target for target in edges.get(current, ()) if target in rel and target not in seen)
    return rel, roots, seen


def self_test():
    with tempfile.TemporaryDirectory(prefix="rust-source-census-") as tmp:
        root = Path(tmp) / "src"
        files = {
            "main.rs": 'mod app;\n',
            "app.rs": (
                'mod outer { fn f() { }\n'
                '    mod child;\n'
                '}\n'
                'mod after;\n'
                '#[cfg_attr(test, path = "fixtures/test_child.rs")]\n'
                'mod test_child;\n'
                'include!("included.rs");\n'
            ),
            "app/outer/child.rs": "// reached through inline module\n",
            "app/after.rs": "// reached after closed inline module\n",
            "fixtures/test_child.rs": "// reached through cfg_attr(path)\n",
            "included.rs": "// reached through include!\n",
            "bin/second.rs": "mod from_second_bin;\n",
            "bin/from_second_bin.rs": "// second crate root\n",
            "orphan.rs": "mod child;\n",
            "orphan/child.rs": "// must not be made reachable by its orphan parent\n",
        }
        for name, contents in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(contents)
        rel, roots, seen = source_graph(root)
        unreachable = set(rel) - seen
        expected = {"orphan.rs", "orphan/child.rs"}
        if unreachable != expected:
            raise AssertionError(f"expected only disconnected orphan subtree {expected}; got {unreachable}")
        if "bin/second.rs" not in roots or "bin/from_second_bin.rs" not in seen:
            raise AssertionError("second bin root was not traversed")
    print("Rust source reachability fixtures: 5 cases passed")


def main(argv):
    if argv == ["--self-test"]:
        self_test()
        return
    if len(argv) != 1:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} <Rust source root> | --self-test")
    root = Path(argv[0])
    rel, roots, seen = source_graph(root)
    unreachable = sorted(set(rel) - seen)
    if unreachable:
        print("Rust source files unreachable from crate roots:", file=sys.stderr)
        print("\n".join(f"  {name}" for name in unreachable), file=sys.stderr)
        raise SystemExit(1)
    print(f"Rust source reachability: {len(seen)} files reachable from {len(roots)} crate roots")


if __name__ == "__main__":
    main(sys.argv[1:])
