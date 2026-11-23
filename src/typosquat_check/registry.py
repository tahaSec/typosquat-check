"""Optional online checks against the PyPI / npm registries."""

from __future__ import annotations

import datetime as dt
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from . import __version__
from .detect import Finding

UA = "typosquat-check/%s (+https://github.com/tahaSec/typosquat-check)" % __version__


def _get_json(url: str, timeout: float) -> Optional[dict]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def _parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def lookup(name: str, ecosystem: str, timeout: float = 10.0) -> Optional[dict]:
    """Return {"created": datetime, "versions": int} or None if the package does not exist."""
    if ecosystem == "pypi":
        data = _get_json("https://pypi.org/pypi/%s/json" % urllib.parse.quote(name), timeout)
        if data is None:
            return None
        uploads = [f["upload_time_iso_8601"] for files in data.get("releases", {}).values() for f in files
                   if f.get("upload_time_iso_8601")]
        created = min(map(_parse_time, uploads)) if uploads else None
        return {"created": created, "versions": len(data.get("releases", {}))}
    data = _get_json("https://registry.npmjs.org/%s" % urllib.parse.quote(name, safe="@"), timeout)
    if data is None:
        return None
    created = data.get("time", {}).get("created")
    return {"created": _parse_time(created) if created else None, "versions": len(data.get("versions", {}))}


def online_check(name: str, ecosystem: str, file=None, line=None, timeout: float = 10.0,
                 now: Optional[dt.datetime] = None, new_days: int = 30) -> Optional[Finding]:
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        info = lookup(name, ecosystem, timeout)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return Finding(ecosystem, name, "info", "registry lookup failed: %s" % exc, file=file, line=line)
    if info is None:
        return Finding(ecosystem, name, "high",
                       "does not exist on the registry. Anyone can register this name "
                       "(slopsquatting / dependency confusion). Was it suggested by an AI?",
                       file=file, line=line)
    created = info.get("created")
    if created and (now - created).days < new_days:
        return Finding(ecosystem, name, "medium",
                       "package is only %d day(s) old with %d version(s). Review it before installing"
                       % ((now - created).days, info["versions"]), file=file, line=line)
    return None
