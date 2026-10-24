import io
import json
import zipfile

import pytest

from supply_chain_sweep.collectors.caches import parse_npm_tarball_url, parse_wheel_filename
from supply_chain_sweep.collectors.lockfiles import parse_package_lock, parse_poetry_lock, parse_requirements
from supply_chain_sweep.intel.osv import OsvDB, is_malicious, sync
from supply_chain_sweep.intel.profiles import parse_profile
from supply_chain_sweep.util import normalize_digest
from supply_chain_sweep.versions import is_affected


@pytest.mark.parametrize("version,expected", [("1.0.0", False), ("1.2.0", True), ("1.4.9", True), ("1.5.0", False), ("2.0.1", True)])
def test_pypi_ranges(version, expected):
    aff = {"ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "1.2"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"last_affected": "2.0.1"}]}]}
    assert is_affected("PyPI", version, aff) is expected


@pytest.mark.parametrize("version,expected", [("1.0.0-rc.1", True), ("1.0.0", False), ("0.9.9", True), ("v0.1.0", True)])
def test_semver_ranges(version, expected):
    aff = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]}
    assert is_affected("npm", version, aff) is expected


def test_explicit_versions_normalised():
    assert is_affected("PyPI", "1.82.8", {"versions": ["1.82.8"]})
    assert is_affected("PyPI", "1.0", {"versions": ["1.0.0"]})
    assert not is_affected("PyPI", "1.82.9", {"versions": ["1.82.8"]})


def test_digest_forms():
    hexd = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
    assert normalize_digest(hexd) == f"sha256:{hexd}"
    assert normalize_digest(f"sha256:{hexd.upper()}") == f"sha256:{hexd}"
    assert normalize_digest("sha256=ceNa7wMJnNHy1kRnNCcwJaFjWX3pORLfMh7xGL8TUjg") == f"sha256:{hexd}"
    assert normalize_digest("sha1-" + "AAAAAAAAAAAAAAAAAAAAAAAAAAA=") == "sha1:" + "0" * 40
    assert normalize_digest("garbage") is None


def test_filename_parsers():
    assert parse_wheel_filename("litellm-1.82.8-py3-none-any.whl") == ("litellm", "1.82.8")
    assert parse_npm_tarball_url("https://registry.npmjs.org/@scope/my-pkg/-/my-pkg-1.0.0-beta.1.tgz") == ("@scope/my-pkg", "1.0.0-beta.1")
    assert parse_npm_tarball_url("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz") == ("left-pad", "1.3.0")


def test_lockfile_parsers(tmp_path):
    reqs = parse_requirements(tmp_path / "r.txt", "a==1.0 \\\n    --hash=sha256:" + "c" * 64 + "\nB[x]===2.0 ; python_version>'3'\nc>=1\n-e .\n")
    assert [(p.name, p.version) for p in reqs] == [("a", "1.0"), ("B", "2.0")]
    assert reqs[0].hashes == ["sha256:" + "c" * 64]
    poetry = parse_poetry_lock(tmp_path / "poetry.lock", {"package": [{"name": "x", "version": "1"}],
                                                         "metadata": {"files": {"x": [{"hash": "sha256:" + "d" * 64}]}}})
    assert poetry[0].hashes == ["sha256:" + "d" * 64]
    v1 = parse_package_lock(tmp_path / "package-lock.json", {"dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}})
    assert [(p.name, p.version) for p in v1] == [("a", "1.0.0"), ("b", "2.0.0")]


def test_malicious_classification():
    assert is_malicious({"id": "MAL-2024-1"})
    assert is_malicious({"id": "PYSEC-1", "aliases": ["MAL-2024-1"]})
    assert is_malicious({"id": "GHSA-x", "database_specific": {"cwe_ids": ["CWE-506"]}})
    assert is_malicious({"id": "GHSA-y", "summary": "Two LiteLLM versions published containing credential harvesting malware"})
    assert not is_malicious({"id": "GHSA-z", "summary": "SQL injection in proxy"})


def test_profile_validation():
    with pytest.raises(ValueError, match="move top-level keys"):
        parse_profile({"id": "x", "packages": [{"name": "a", "hashes": ["0" * 64]}]}, "t")
    with pytest.raises(ValueError, match="unrecognised hash"):
        parse_profile({"id": "x", "hashes": ["nothex"]}, "t")


def test_osv_sync_full_then_incremental(tmp_path):
    rec1 = {"id": "MAL-1", "modified": "2026-01-01T00:00:00Z", "affected": [{"package": {"ecosystem": "PyPI", "name": "Evil_Pkg"}, "versions": ["1.0"]}]}
    rec2 = {"id": "MAL-2", "modified": "2026-02-01T00:00:00.5Z", "affected": [{"package": {"ecosystem": "PyPI", "name": "worse"}, "versions": ["2.0"]}]}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("MAL-1.json", json.dumps(rec1))
    files = {"PyPI/all.zip": buf.getvalue(),
             "PyPI/modified_id.csv": b"2026-02-01T00:00:00.5Z,MAL-2\n2026-01-01T00:00:00Z,MAL-1\n",
             "PyPI/MAL-2.json": json.dumps(rec2).encode()}
    fetched = []

    def opener(url):
        key = url.split(".com/", 1)[1]
        fetched.append(key)
        return io.BytesIO(files[key])

    db = OsvDB(tmp_path / "osv.db")
    assert sync(db, ["PyPI"], opener=opener, log=lambda m: None) == []
    assert [a for a, _ in db.candidates("PyPI", "evil-pkg")] == ["MAL-1"]
    assert sync(db, ["PyPI"], opener=opener, log=lambda m: None) == []
    assert fetched == ["PyPI/all.zip", "PyPI/modified_id.csv", "PyPI/MAL-2.json"]
    assert [a for a, _ in db.candidates("PyPI", "worse")] == ["MAL-2"]
    fetched.clear()
    sync(db, ["PyPI"], opener=opener, log=lambda m: None)
    assert fetched == ["PyPI/modified_id.csv"]  # nothing new
