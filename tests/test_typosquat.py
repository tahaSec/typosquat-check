import datetime as dt
import json

import pytest

from typosquat_check import check_name
from typosquat_check import registry
from typosquat_check.cli import main
from typosquat_check.detect import damerau_levenshtein, normalize
from typosquat_check.parsers import discover, parse_file


# --- detection -----------------------------------------------------------------

@pytest.mark.parametrize("name,eco,target", [
    ("reqeusts", "pypi", "requests"),      # transposition
    ("requets", "pypi", "requests"),       # deletion
    ("djnago", "pypi", "django"),
    ("urlib3", "pypi", "urllib3"),
    ("beautifulsup4", "pypi", "beautifulsoup4"),
    ("expres", "npm", "express"),
    ("lodahs", "npm", "lodash"),
    ("react_dom", "npm", "react-dom"),     # separator confusion
    ("@typess/node", "npm", "@types/node"),
])
def test_typos_are_high(name, eco, target):
    f = check_name(name, eco)
    assert f is not None and f.severity == "high" and f.similar_to == target, f


@pytest.mark.parametrize("name,eco", [
    ("colourama", "pypi"), ("python3-dateutil", "pypi"), ("jeIlyfish", "pypi"), ("crossenv", "npm"),
])
def test_known_malicious_is_critical(name, eco):
    assert check_name(name, eco).severity == "critical"


@pytest.mark.parametrize("name,eco", [
    ("requests", "pypi"), ("Django", "pypi"), ("python_dateutil", "pypi"), ("typing.extensions", "pypi"),
    ("express", "npm"), ("react-dom", "npm"), ("@types/node", "npm"), ("lodash", "npm"),
])
def test_popular_names_are_clean(name, eco):
    assert check_name(name, eco) is None


def test_homoglyph_rn_for_m():
    f = check_name("nurnpy", "pypi")  # 'rn' looks like 'm' -> numpy
    assert f is not None and f.similar_to == "numpy"


def test_affix_impersonation_is_medium():
    f = check_name("requests-python", "pypi")
    assert f is not None and f.severity == "medium" and f.similar_to == "requests"


def test_unrelated_new_name_is_clean():
    assert check_name("my-totally-unique-internal-lib", "pypi") is None


def test_normalize_pep503():
    assert normalize("Typing_Extensions", "pypi") == "typing-extensions"
    assert normalize("Foo_Bar", "npm") == "foo_bar"


def test_damerau_levenshtein():
    assert damerau_levenshtein("abcd", "abdc") == 1
    assert damerau_levenshtein("kitten", "sitting", limit=5) == 3
    assert damerau_levenshtein("a", "abcdef", limit=2) == 3  # early exit


# --- parsers ---------------------------------------------------------------------

def test_requirements_parser(tmp_path):
    (tmp_path / "base.txt").write_text("numpy==1.26\n")
    req = tmp_path / "requirements.txt"
    req.write_text(
        "# comment\n"
        "-r base.txt\n"
        "reqeusts>=2.0  # typo\n"
        "flask[async]==3.0 ; python_version > '3.8'\n"
        "-e git+https://github.com/x/y.git#egg=mylib\n"
        "--index-url https://pypi.org/simple\n"
        "./local/path\n"
        "https://example.com/pkg.whl\n"
    )
    names = [(d.name, d.line) for d in parse_file(req)]
    assert names == [("numpy", 1), ("reqeusts", 3), ("flask", 4), ("mylib", 5)]


def test_pyproject_parser(tmp_path):
    p = tmp_path / "pyproject.toml"
    p.write_text(
        '[project]\nname = "x"\ndependencies = ["requests>=2", "urlib3"]\n'
        '[project.optional-dependencies]\ndev = ["pytest"]\n'
        '[tool.poetry.dependencies]\npython = "^3.11"\ndjnago = "^5"\n'
    )
    names = {d.name for d in parse_file(p)}
    assert names == {"requests", "urlib3", "pytest", "djnago"}


def test_package_json_parser(tmp_path):
    p = tmp_path / "package.json"
    p.write_text(json.dumps({
        "dependencies": {"expres": "^4", "local": "file:../local", "aliased": "npm:lodahs@^4"},
        "devDependencies": {"@types/node": "^20", "gitdep": "github:user/repo"},
    }, indent=2))
    deps = {d.name: d.line for d in parse_file(p)}
    assert set(deps) == {"expres", "lodahs", "@types/node"}
    assert deps["expres"] == 3


def test_discover_skips_node_modules(tmp_path):
    (tmp_path / "requirements-dev.txt").write_text("pytest\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text("{}")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package.json").write_text("{}")
    names = sorted(p.relative_to(tmp_path).as_posix() for p in discover(tmp_path))
    assert names == ["requirements-dev.txt", "web/package.json"]


# --- online (mocked) --------------------------------------------------------------

def test_online_missing_package(monkeypatch):
    monkeypatch.setattr(registry, "lookup", lambda *a, **k: None)
    f = registry.online_check("hallucinated-pkg", "pypi")
    assert f.severity == "high" and "does not exist" in f.reason


def test_online_brand_new_package(monkeypatch):
    now = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)
    monkeypatch.setattr(registry, "lookup",
                        lambda *a, **k: {"created": now - dt.timedelta(days=3), "versions": 1})
    f = registry.online_check("fresh-pkg", "npm", now=now)
    assert f.severity == "medium" and "3 day" in f.reason


def test_online_old_package_ok(monkeypatch):
    monkeypatch.setattr(registry, "lookup",
                        lambda *a, **k: {"created": dt.datetime(2015, 1, 1, tzinfo=dt.timezone.utc), "versions": 40})
    assert registry.online_check("old-pkg", "pypi") is None


# --- CLI -------------------------------------------------------------------------

def test_cli_direct_names(capsys):
    assert main(["--pypi", "requests", "--npm", "express"]) == 0
    assert main(["--pypi", "reqeusts"]) == 1
    out = capsys.readouterr().out
    assert "did you mean: requests" in out


def test_cli_json(tmp_path, capsys):
    req = tmp_path / "requirements.txt"
    req.write_text("colourama\nrequests\n")
    assert main([str(tmp_path), "-f", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data[0]["package"] == "colourama" and data[0]["line"] == 1
