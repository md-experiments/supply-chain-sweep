import json
import os

from supply_chain_sweep.cli import main
from supply_chain_sweep.models import Severity
from supply_chain_sweep.report import to_json, to_sarif
from supply_chain_sweep.scanner import ScanOptions, run_scan


def by_rule(result, rule):
    return [f for f in result.findings if f.rule == rule]


def test_full_scan_finds_compromise(cfg, host):
    result = run_scan(cfg, ScanOptions())
    assert result.has_critical

    mal = {(f.package["name"], f.package["version"], f.package["source_type"]) for f in by_rule(result, "malicious-package")}
    assert ("litellm", "1.82.8", "environment") in mal  # venv
    assert ("litellm", "1.82.7", "environment") in mal  # conda env, matched via PyPI name
    assert ("litellm", "1.82.8", "cache") in mal  # pip wheel cache
    assert ("litellm", "1.82.7", "lockfile") in mal  # requirements.txt
    assert ("litellm", "1.107.0", "lockfile") in mal  # uv.lock
    assert ("event-stream", "3.3.6", "environment") in mal  # GHSA with CWE-506
    assert ("event-stream", "3.3.6", "cache") in mal  # npm cacache
    assert ("event-stream", "3.3.6", "lockfile") in mal  # package-lock.json
    assert ("flatmap-stream", "0.1.1", "environment") in mal  # nested node_modules, range introduced=0

    venv_hit = next(f for f in by_rule(result, "malicious-package") if f.package["source_type"] == "environment"
                    and f.package["name"] == "litellm" and "1.82.8" == f.package["version"])
    assert venv_hit.advisory == "MAL-2026-2144"
    assert "litellm-2026" in venv_hit.details["advisories"]

    # Profile hash of litellm_init.pth does not match the fixture, but the file name does.
    files = by_rule(result, "ioc-file")
    assert any(f.location.endswith("site-packages/litellm_init.pth") for f in files)
    # Persistence path from the built-in profile, resolved against the home dir.
    persist = by_rule(result, "ioc-persistence")
    assert [p.location for p in persist] == [str(host / "home/.config/sysmon/sysmon.py")]

    # Ordinary CVE is info and aliases are collapsed into one advisory.
    vuln = by_rule(result, "vulnerable-package")
    assert len(vuln) == 1 and vuln[0].severity is Severity.INFO
    assert vuln[0].details["advisories"] == ["GHSA-x84v-xcm2-53pg"]


def test_pth_heuristic(cfg):
    result = run_scan(cfg, ScanOptions())
    names = sorted(os.path.basename(f.location) for f in by_rule(result, "pth-exec"))
    # litellm_init.pth is already critical; benign virtualenv/setuptools/path-only files are allowlisted.
    assert names == ["unknown-hook.pth"]
    assert by_rule(result, "pth-exec")[0].severity is Severity.HIGH


def test_pth_allowlist_from_config(cfg):
    from supply_chain_sweep.config import PthAllow

    cfg.pth_allowlist.append(PthAllow(name="unknown-hook.pth", contains="sys.path.insert"))
    assert not by_rule(run_scan(cfg, ScanOptions()), "pth-exec")


def test_hash_ioc_regardless_of_version(cfg, host, tmp_path):
    # Same malicious .pth content shipped under a different package name and version.
    import hashlib

    from tests.conftest import MALICIOUS_PTH, make_dist

    site = host / "projects" / "web" / "venv" / "lib" / "python3.11" / "site-packages"
    make_dist(site, "innocent", "9.9.9", {"zz_payload.pth": MALICIOUS_PTH.encode()})
    profile = tmp_path / "p.toml"
    profile.write_text('id = "custom"\nhashes = ["sha256:%s"]\n' % hashlib.sha256(MALICIOUS_PTH.encode()).hexdigest())
    result = run_scan(cfg, ScanOptions(extra_profiles=[profile]))
    hits = by_rule(result, "ioc-hash")
    assert any(f.package and f.package["name"] == "innocent" for f in hits)
    assert any(f.location.endswith("zz_payload.pth") for f in hits)


def test_log_domain_search(cfg, tmp_path):
    log = tmp_path / "dns.log"
    log.write_text("ok example.com\nquery A models.litellm.cloud from 10.0.0.2\nnotlitellm.cloudy.com\n")
    result = run_scan(cfg, ScanOptions(logs=[log]))
    hits = by_rule(result, "ioc-domain")
    assert len(hits) >= 1
    assert all(h.details["lines"] == [2] for h in hits)


def test_filter_profile_and_path(cfg, host):
    result = run_scan(cfg, ScanOptions(paths=[host / "projects" / "site"], profile="litellm-2026"))
    # Only the npm project is scanned and only the litellm profile is checked: nothing to find.
    assert not result.findings
    assert {p.ecosystem.value for p in result.packages} == {"npm"}


def test_inventory_persisted_and_diff(cfg, host):
    first = run_scan(cfg, ScanOptions())
    assert first.diff.previous_scan is None
    assert first.new_critical

    from tests.conftest import make_dist
    site = host / "projects" / "web" / "venv" / "lib" / "python3.11" / "site-packages"
    make_dist(site, "rich", "13.0.0")
    second = run_scan(cfg, ScanOptions())
    assert second.diff.previous_scan == first.scan_id
    assert [a["name"] for a in second.diff.added] == ["rich"]
    assert not second.new_critical  # same criticals as before: no new alert


def test_deterministic_output(cfg):
    a = to_json(run_scan(cfg, ScanOptions(persist=False)))
    b = to_json(run_scan(cfg, ScanOptions(persist=False)))
    for d in (a, b):
        d.pop("scan")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_read_only(cfg, host):
    def snapshot():
        out = {}
        for dirpath, _, files in os.walk(host):
            for f in files:
                p = os.path.join(dirpath, f)
                st = os.stat(p)
                out[p] = (st.st_size, st.st_mtime_ns)
        return out

    before = snapshot()
    run_scan(cfg, ScanOptions())
    assert snapshot() == before


def test_missing_path_is_warning(cfg, tmp_path):
    result = run_scan(cfg, ScanOptions(paths=[tmp_path / "nope"]))
    assert any("does not exist" in w.message for w in result.warnings.items)


def test_sarif_shape(cfg):
    sarif = to_sarif(run_scan(cfg, ScanOptions(persist=False)))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert {r["level"] for r in run["results"]} >= {"error", "warning", "note"}
    assert all(r["ruleId"] in {x["id"] for x in run["tool"]["driver"]["rules"]} for r in run["results"])


def test_cli_exit_code(cfg, host, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SWEEP_HOME", str(cfg.data_dir))
    monkeypatch.setenv("SWEEP_CONFIG", str(tmp_path / "none.toml"))
    out = tmp_path / "r.json"
    code = main(["--offline", "--only-roots", "--root", str(host / "projects" / "agent"), "--no-images",
                 "--no-caches", "--json", str(out)])
    assert code == 1
    data = json.loads(out.read_text())
    assert data["summary"]["critical"] >= 1
    code = main(["scan", "--offline", "--path", str(host / "projects" / "web"), "--no-images", "--profile", "litellm-2026"])
    assert code == 0
