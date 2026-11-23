"""Read dependency names from common manifest files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator, List, NamedTuple, Optional, Set

try:  # Python 3.11+
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - Python 3.9 / 3.10
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        tomllib = None


class Dep(NamedTuple):
    name: str
    ecosystem: str  # "pypi" or "npm"
    file: str
    line: Optional[int]


REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
PEP508_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def parse_requirements(path: Path, _seen: Optional[Set[Path]] = None) -> Iterator[Dep]:
    seen = _seen if _seen is not None else set()
    real = path.resolve()
    if real in seen or not path.is_file():
        return
    seen.add(real)
    for lineno, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            include = line.split(None, 1)[1].strip()
            yield from parse_requirements(path.parent / include, seen)
            continue
        if line.startswith("-e ") or line.startswith("--editable "):
            m = re.search(r"#egg=([A-Za-z0-9._-]+)", raw)
            if m:
                yield Dep(m.group(1), "pypi", str(path), lineno)
            continue
        if line.startswith("-") or "://" in line.split("@")[0] or line.startswith((".", "/")):
            continue  # options, URLs, local paths
        m = REQ_NAME.match(line)
        if m:
            yield Dep(m.group(1), "pypi", str(path), lineno)


def _line_of(text: str, name: str) -> Optional[int]:
    m = re.search(r"""^[^\n]*["']?%s["']?\s*[:=<>~!\[;\s,"']""" % re.escape(name), text, re.M | re.I)
    return text.count("\n", 0, m.start()) + 1 if m else None


def parse_pyproject(path: Path) -> Iterator[Dep]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if tomllib is None:  # pragma: no cover
        return
    data = tomllib.loads(text)
    specs: List[str] = []
    project = data.get("project", {})
    specs += project.get("dependencies", [])
    for group in (project.get("optional-dependencies") or {}).values():
        specs += group
    for group in (data.get("dependency-groups") or {}).values():
        specs += [g for g in group if isinstance(g, str)]
    names = [m.group(1) for s in specs if (m := PEP508_NAME.match(s))]
    poetry = data.get("tool", {}).get("poetry", {})
    for key in ("dependencies", "dev-dependencies"):
        names += [n for n in (poetry.get(key) or {}) if n.lower() != "python"]
    for group in (poetry.get("group") or {}).values():
        names += [n for n in (group.get("dependencies") or {}) if n.lower() != "python"]
    for n in dict.fromkeys(names):
        yield Dep(n, "pypi", str(path), _line_of(text, n))


def parse_package_json(path: Path) -> Iterator[Dep]:
    text = path.read_text(encoding="utf-8", errors="replace")
    data = json.loads(text)
    seen = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, spec in (data.get(key) or {}).items():
            if name in seen:
                continue
            seen.add(name)
            # "alias": "npm:real-package@^1" installs real-package
            if isinstance(spec, str) and spec.startswith("npm:"):
                rest = spec[4:]
                real = rest[: rest.index("@", 1)] if "@" in rest[1:] else rest
                yield Dep(real, "npm", str(path), _line_of(text, name))
            elif isinstance(spec, str) and re.match(r"^(file:|link:|workspace:|git|https?:|github:)", spec):
                continue
            else:
                yield Dep(name, "npm", str(path), _line_of(text, name))


def parse_file(path: Path) -> Iterator[Dep]:
    name = path.name.lower()
    if name == "package.json":
        yield from parse_package_json(path)
    elif name == "pyproject.toml":
        yield from parse_pyproject(path)
    elif name.endswith(".txt") or name.endswith(".in"):
        yield from parse_requirements(path)
    else:
        raise ValueError("unsupported file: %s" % path)


def discover(root: Path) -> List[Path]:
    skip = {"node_modules", ".git", ".venv", "venv", "env", "__pycache__", "dist", "build", "site-packages"}
    found = []
    for p in sorted(root.rglob("*")):
        if any(part in skip for part in p.relative_to(root).parts):
            continue
        n = p.name.lower()
        if p.is_file() and (n in ("package.json", "pyproject.toml")
                            or (n.startswith("requirements") and n.endswith((".txt", ".in")))):
            found.append(p)
    return found
