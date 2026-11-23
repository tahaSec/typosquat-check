"""Typosquatting detection against a list of popular package names."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from functools import lru_cache
from importlib import resources
from typing import Dict, List, Optional, Tuple

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# How many of the most downloaded packages count as "worth impersonating".
TARGET_COUNT = 5000
# Typos of packages above this rank are reported as high/medium, below it as low.
HIGH_RANK = 1500

# Packages publicly documented as malicious typosquats. Kept short on purpose:
# a package being on this list is certain, not a heuristic.
KNOWN_MALICIOUS = {
    "pypi": {
        "colourama": "colorama",          # 2018, clipboard crypto-stealer
        "python3-dateutil": "python-dateutil",  # 2019, SSH/GPG key stealer
        "jeilyfish": "jellyfish",          # 2019, capital i instead of l
    },
    "npm": {
        "crossenv": "cross-env",          # 2017, environment variable stealer
    },
}

AFFIXES_PREFIX = ("python-", "python3-", "py-", "py", "node-", "js-", "the-", "lib")
AFFIXES_SUFFIX = ("-python", "-py", "py", "-js", "js", "-node", "-lib", "-dev", "-api", "-sdk",
                  "2", "3", "-cli", "s")

HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("1", "l"), ("0", "o"), ("5", "s"), ("cl", "d"))


@dataclass
class Finding:
    ecosystem: str
    package: str
    severity: str
    reason: str
    similar_to: Optional[str] = None
    rank: Optional[int] = None
    file: Optional[str] = None
    line: Optional[int] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


def normalize(name: str, ecosystem: str) -> str:
    name = name.strip().lower()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name)  # PEP 503
    return name


@lru_cache(maxsize=None)
def popular(ecosystem: str) -> Tuple[Dict[str, int], List[str]]:
    """Return ({normalized_name: rank}, [top targets in rank order])."""
    text = resources.files("typosquat_check").joinpath("data/%s.txt" % ecosystem).read_text(encoding="utf-8")
    names = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    ranks: Dict[str, int] = {}
    for i, n in enumerate(names, 1):
        ranks.setdefault(normalize(n, ecosystem), i)
    targets = [normalize(n, ecosystem) for n in names[:TARGET_COUNT]]
    return ranks, targets


def damerau_levenshtein(a: str, b: str, limit: int = 3) -> int:
    """Optimal string alignment distance, with early exit above ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: List[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        row_min = cur[0]
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
            row_min = min(row_min, cur[j])
        if row_min > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _strip_separators(name: str) -> str:
    return re.sub(r"[-_.]", "", name)


def _deglyph(name: str) -> str:
    for fake, real in HOMOGLYPHS:
        name = name.replace(fake, real)
    return name


def check_name(name: str, ecosystem: str) -> Optional[Finding]:
    """Return a Finding if ``name`` looks like a typosquat, else None."""
    norm = normalize(name, ecosystem)
    if not norm:
        return None

    bad = KNOWN_MALICIOUS.get(ecosystem, {})
    if norm in bad:
        return Finding(ecosystem, name, "critical",
                       "known malicious typosquat of '%s'" % bad[norm], similar_to=bad[norm])

    ranks, targets = popular(ecosystem)
    if norm in ranks:
        return None  # itself a popular, established package

    scope, _, bare = norm.rpartition("/") if norm.startswith("@") else ("", "", norm)

    best: Optional[Finding] = None

    def consider(sev: str, reason: str, target: str):
        nonlocal best
        rank = ranks[target]
        cand = Finding(ecosystem, name, sev, reason, similar_to=target, rank=rank)
        if best is None or (SEVERITY_ORDER[sev], -rank) > (SEVERITY_ORDER[best.severity], -best.rank):
            best = cand

    deglyphed = _deglyph(norm)
    stripped = _strip_separators(norm)
    for target in targets:
        if target == norm:
            continue
        # 1. homoglyph / look-alike characters (rn -> m, 1 -> l, ...)
        if deglyphed != norm and deglyphed == target:
            consider("high", "look-alike characters of '%s'" % target, target)
            continue
        # 2. separator confusion (npm treats - _ . as different names)
        if ecosystem == "npm" and stripped == _strip_separators(target) and len(stripped) >= 4:
            consider("high", "same letters as '%s' with different separators" % target, target)
            continue
        # 3. edit distance
        rank = ranks[target]
        if len(target) >= 5 and abs(len(target) - len(norm)) <= 2:
            d = damerau_levenshtein(norm, target, limit=2)
            if d == 1:
                # Attackers go after the most downloaded names; further down the
                # list, near-identical legitimate names are common.
                if rank <= HIGH_RANK and len(target) >= 6:
                    consider("high", "one-character typo of '%s'" % target, target)
                elif rank <= HIGH_RANK:
                    consider("medium", "one-character typo of '%s'" % target, target)
                else:
                    consider("low", "one character away from '%s'" % target, target)
                continue
            if d == 2 and len(target) >= 10 and rank <= HIGH_RANK:
                consider("medium", "two-character typo of '%s'" % target, target)
                continue
        # 4. impersonation with common prefixes / suffixes
        if len(target) >= 4 and rank <= HIGH_RANK:
            target_bare = target.rpartition("/")[2]
            for p in AFFIXES_PREFIX:
                if bare == p + target_bare:
                    consider("medium", "'%s' with added prefix '%s'" % (target, p), target)
            for s in AFFIXES_SUFFIX:
                if bare == target_bare + s:
                    consider("medium", "'%s' with added suffix '%s'" % (target, s), target)
        # 5. scope squatting (@types/node vs @typess/node)
        if scope and target.startswith("@"):
            tscope, _, tbare = target.partition("/")
            if tbare == bare and tscope != scope and damerau_levenshtein(scope, tscope, 1) == 1:
                consider("high", "look-alike scope of '%s'" % target, target)

    return best
