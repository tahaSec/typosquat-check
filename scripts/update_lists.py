"""Refresh the bundled popular-package lists.

python scripts/update_lists.py
"""

import json
import re
import urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "src" / "typosquat_check" / "data"
PYPI = "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json"
NPM = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top-download.js"


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read().decode("utf-8")


def main() -> None:
    data = json.loads(fetch(PYPI))
    names = [row["project"] for row in data["rows"]]
    (DATA / "pypi.txt").write_text(
        "# Top PyPI projects by downloads. Source: github.com/hugovk/top-pypi-packages (%s)\n"
        % data["last_update"][:10] + "\n".join(names) + "\n", encoding="utf-8")
    npm = re.findall(r"^\s*'([^']+)',?$", fetch(NPM), re.M)
    (DATA / "npm.txt").write_text(
        "# Top npm packages by downloads. Source: github.com/wooorm/npm-high-impact\n"
        + "\n".join(npm) + "\n", encoding="utf-8")
    print("pypi: %d names, npm: %d names" % (len(names), len(npm)))


if __name__ == "__main__":
    main()
