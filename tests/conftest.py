"""Fixtures: a fake host with a compromised environment, clean environments, caches and lockfiles."""

from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from supply_chain_sweep.config import Config
from supply_chain_sweep.intel.osv import OsvDB

MALICIOUS_PTH = "import os, base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"


def record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def make_dist(site: Path, name: str, version: str, files: dict[str, bytes] | None = None, installer: str = "pip") -> Path:
    di = site / f"{name.replace('-', '_')}-{version}.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nlong description\n")
    (di / "INSTALLER").write_text(installer + "\n")
    rows = []
    for rel, data in (files or {}).items():
        target = site / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        rows.append(f"{rel},{record_hash(data)},{len(data)}")
    rows.append(f"{di.name}/RECORD,,")
    (di / "RECORD").write_text("\n".join(rows) + "\n")
    return di


@pytest.fixture
def host(tmp_path: Path) -> Path:
    root = tmp_path / "host"

    # Compromised venv: litellm 1.82.8 with its .pth payload.
    bad = root / "projects" / "agent" / ".venv"
    site = bad / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (bad / "pyvenv.cfg").write_text("home = /usr/bin\n")
    make_dist(site, "litellm", "1.82.8", {"litellm/__init__.py": b"", "litellm_init.pth": MALICIOUS_PTH.encode()})
    make_dist(site, "requests", "2.19.0", {"requests/__init__.py": b""})

    # Clean venv with benign .pth files.
    good = root / "projects" / "web" / "venv"
    gsite = good / "lib" / "python3.11" / "site-packages"
    gsite.mkdir(parents=True)
    (good / "pyvenv.cfg").write_text("home = /usr/bin\n")
    make_dist(gsite, "flask", "3.0.0", {"flask/__init__.py": b""})
    (gsite / "_virtualenv.pth").write_text("import _virtualenv")
    (gsite / "distutils-precedence.pth").write_text(
        "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; "
        "enabled and __import__('_distutils_hack').add_shim(); "
    )
    (gsite / "paths.pth").write_text("/opt/extra/lib\n")
    (gsite / "unknown-hook.pth").write_text("import sys; sys.path.insert(0, '/x')\n")

    # Conda env (conda-meta) plus a package cache.
    conda = root / "miniconda3"
    (conda / "conda-meta").mkdir(parents=True)
    (conda / "conda-meta" / "litellm-1.82.7-pyhd8ed1ab_0.json").write_text(
        json.dumps({"name": "litellm", "version": "1.82.7", "build": "pyhd8ed1ab_0", "files": []})
    )
    (conda / "conda-meta" / "numpy-1.26.0-py311_0.json").write_text(
        json.dumps({"name": "numpy", "version": "1.26.0", "build": "py311_0", "files": []})
    )
    pkgs = conda / "pkgs"
    pkgs.mkdir()
    (pkgs / "urls.txt").write_text("")
    (pkgs / "numpy-base-1.26.0-py311_0.conda").write_bytes(b"not really an archive")

    # node_modules with a malicious npm version and a clean one.
    nm = root / "projects" / "site" / "node_modules"
    for name, ver in (("event-stream", "3.3.6"), ("left-pad", "1.3.0"), ("@scope/util", "2.0.0")):
        d = nm / name
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": name, "version": ver}))
    nested = nm / "event-stream" / "node_modules" / "flatmap-stream"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text(json.dumps({"name": "flatmap-stream", "version": "0.1.1",
                                                      "scripts": {"postinstall": "node x.js"}}))

    # Lockfiles.
    proj = root / "projects" / "agent"
    (proj / "requirements.txt").write_text("litellm==1.82.7 --hash=sha256:" + "a" * 64 + "\nflask>=2\n")
    (proj / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "litellm"\nversion = "1.107.0"\n'
        'wheels = [{ url = "https://x/litellm.whl", hash = "sha256:' + "b" * 64 + '" }]\n'
    )
    (root / "projects" / "site" / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"name": "site"}, "node_modules/event-stream": {"version": "3.3.6", "integrity": "sha512-" + base64.b64encode(b"x" * 64).decode()}},
    }))

    # Home with pip / npm caches and a persistence file.
    home = root / "home"
    wheels = home / ".cache" / "pip" / "wheels" / "ab" / "cd"
    wheels.mkdir(parents=True)
    whl = wheels / "litellm-1.82.8-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        zf.writestr("litellm-1.82.8.dist-info/METADATA", "Name: litellm\nVersion: 1.82.8\n")
    idx = home / ".npm" / "_cacache" / "index-v5" / "aa" / "bb"
    idx.mkdir(parents=True)
    entry = {"key": "make-fetch-happen:request-cache:https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz",
             "integrity": "sha512-" + base64.b64encode(b"y" * 64).decode()}
    (idx / "deadbeef").write_text("\n" + "0" * 40 + "\t" + json.dumps(entry) + "\n")
    persist = home / ".config" / "sysmon"
    persist.mkdir(parents=True)
    (persist / "sysmon.py").write_text("# backdoor\n")
    return root


OSV_RECORDS = [
    {
        "id": "MAL-2026-2144",
        "modified": "2026-10-21T22:01:01.881791175Z",
        "aliases": ["PYSEC-2026-2"],
        "summary": "Malicious code in litellm (PyPI)",
        "affected": [{"package": {"name": "litellm", "ecosystem": "PyPI"}, "versions": ["1.82.7", "1.82.8", "1.107.0"]}],
        "database_specific": {"iocs": {"domains": ["litellm.cloud"], "files": [
            {"digests": {"sha256": "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb"},
             "paths": ["litellm-1.107.0.data/purelib/cook.pth"], "source": "PACKAGE_ARCHIVE"},
            {"paths": ["/tmp/.pc_once_test_marker"], "source": "DROPPED"}]}},
    },
    {
        "id": "MAL-2018-1",
        "modified": "2026-01-01T00:00:00Z",
        "summary": "Malicious code in flatmap-stream (npm)",
        "affected": [{"package": {"name": "flatmap-stream", "ecosystem": "npm"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}],
    },
    {
        "id": "GHSA-mh6f-8j2x-4483",
        "modified": "2026-01-01T00:00:00Z",
        "summary": "Critical severity vulnerability that affects event-stream and flatmap-stream",
        "database_specific": {"cwe_ids": ["CWE-506"]},
        "affected": [{"package": {"name": "event-stream", "ecosystem": "npm"}, "versions": ["3.3.6"]}],
    },
    {
        "id": "GHSA-x84v-xcm2-53pg",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2018-18074", "PYSEC-2018-28"],
        "summary": "Insufficiently Protected Credentials in Requests",
        "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
    },
    {
        "id": "PYSEC-2018-28",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
        "summary": "requests credential leak",
        "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
    },
]


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    db = OsvDB(d / "osv.db")
    db.upsert(OSV_RECORDS)
    db.set_feed_state("PyPI", "2026-10-21T22:01:01.881791175Z")
    db.close()
    return d


@pytest.fixture
def cfg(host: Path, data_dir: Path, tmp_path: Path, monkeypatch) -> Config:
    monkeypatch.setenv("HOME", str(host / "home"))
    for var in ("XDG_CACHE_HOME", "PIP_CACHE_DIR", "UV_CACHE_DIR", "npm_config_cache", "CONDA_PKGS_DIRS"):
        monkeypatch.delenv(var, raising=False)
    homes = lambda: [host / "home"]
    monkeypatch.setattr("supply_chain_sweep.discovery.home_dirs", homes)
    monkeypatch.setattr("supply_chain_sweep.matching.home_dirs", homes)
    return Config(roots=[host], profile_dirs=[], docker=False, data_dir=data_dir)
