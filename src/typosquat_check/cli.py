"""Command line interface: ``typosquat-check [paths...]``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List

from . import __version__
from .detect import SEVERITY_ORDER, Finding, check_name
from .parsers import Dep, discover, parse_file

C = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m",
     "info": "\033[37m", "reset": "\033[0m", "bold": "\033[1m", "green": "\033[32m", "dim": "\033[2m"}


def _color() -> bool:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")
    return True


def collect(paths: List[str]) -> List[Dep]:
    deps: List[Dep] = []
    for p in paths:
        path = Path(p)
        files = discover(path) if path.is_dir() else [path]
        for f in files:
            try:
                deps.extend(parse_file(f))
            except (ValueError, OSError) as exc:
                print("typosquat-check: skipping %s: %s" % (f, exc), file=sys.stderr)
    return deps


def analyse(deps: List[Dep], online: bool = False, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    for dep in deps:
        f = check_name(dep.name, dep.ecosystem)
        if f is None and online:
            from .registry import online_check
            f = online_check(dep.name, dep.ecosystem, dep.file, dep.line, timeout=timeout)
        if f is not None:
            f.file, f.line = dep.file, dep.line
            findings.append(f)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file or "", f.line or 0))
    return findings


def render_text(findings: List[Finding], n_deps: int) -> str:
    c = C if _color() else {k: "" for k in C}
    out = []
    for f in findings:
        where = "%s:%s" % (f.file, f.line) if f.file and f.line else (f.file or "<cli>")
        out.append("%s%-8s%s %s%s%s (%s)  %s" % (c[f.severity], f.severity.upper(), c["reset"],
                                                c["bold"], f.package, c["reset"], f.ecosystem, where))
        msg = "         %s" % f.reason
        if f.rank:
            msg += "  [#%d most downloaded]" % f.rank
        out.append(msg)
        if f.similar_to:
            out.append("         %sdid you mean: %s%s" % (c["dim"], f.similar_to, c["reset"]))
    if findings:
        out.append("\n%d suspicious of %d dependencies checked." % (len(findings), n_deps))
    else:
        out.append("%sNo suspicious package names in %d dependencies.%s" % (c["green"], n_deps, c["reset"]))
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="typosquat-check",
                                description="Catch typosquatted and non-existent packages in your dependencies.")
    p.add_argument("paths", nargs="*", help="requirements*.txt, pyproject.toml, package.json or a folder (default: .)")
    p.add_argument("--pypi", nargs="+", default=[], metavar="NAME", help="check PyPI package names directly")
    p.add_argument("--npm", nargs="+", default=[], metavar="NAME", help="check npm package names directly")
    p.add_argument("--online", action="store_true",
                   help="also query PyPI/npm: flag names that do not exist (slopsquatting) or are brand new")
    p.add_argument("-f", "--format", choices=["text", "json"], default="text")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER) + ["never"], default="high")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass
    deps = [Dep(n, "pypi", None, None) for n in args.pypi] + [Dep(n, "npm", None, None) for n in args.npm]
    if args.paths or not deps:
        deps += collect(args.paths or ["."])

    findings = analyse(deps, online=args.online, timeout=args.timeout)
    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print(render_text(findings, len(deps)))

    if args.fail_on == "never":
        return 0
    limit = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= limit for f in findings) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
