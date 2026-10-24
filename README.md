# supply-chain-sweep

Answers one question for a developer machine or build host: **is any known-malicious
Python or npm package version present anywhere on it, and are there signs it ran?**

It sweeps every environment, cache, lockfile and Docker image on the host, not just the
active project, and matches what it finds against a local mirror of
[OSV](https://osv.dev) (including the OpenSSF `MAL-` malicious-package feed) and against
TOML IOC profiles.

**Safe by design:** metadata is read from files only (`METADATA`, `RECORD`,
`conda-meta/*.json`, `package.json`). The scanner never starts a scanned environment's
Python or Node interpreter, so payloads that run on interpreter start (like LiteLLM
1.82.8's `.pth` file) cannot trigger during a scan. It never writes to scanned
locations, and it never sends anything about the host to any service: threat data is
downloaded as OSV's public bulk exports and matched locally.

## Install

```sh
pip install .            # Python 3.11+, one dependency (packaging)
# optional, for Docker images:
#   https://github.com/anchore/syft#installation
```

## Use

```sh
sweep update             # download / incrementally refresh OSV data (PyPI + npm)
sweep                    # full scan (refreshes threat data first; --offline to skip)
sweep --offline --json report.json --sarif report.sarif
sweep --path ~/work/agent          # scan only one path
sweep --profile litellm-2026       # check only one threat profile
sweep --logs /var/log/dnsmasq.log  # also search logs for IOC domains
sweep profiles                     # list loaded IOC profiles
sweep history                      # previous scans
sweep schedule --install           # daily cron entry with --notify (launchd plist on macOS)
```

Exit codes: `0` no critical findings, `1` at least one critical finding, `2` error.

### What it looks at

| Source | Where |
| --- | --- |
| Python environments | every `site-packages` / `dist-packages` under the scan roots: venvs (`pyvenv.cfg`), conda envs, pyenv, uv tools, system and user installs |
| Conda | `conda-meta/*.json` in every env, `pkgs/` caches, `~/.conda/environments.txt`, `.condarc` |
| Caches | pip (`wheels/`, `http-v2/`), uv (`archive-v*`), npm `_cacache`, conda `pkgs/` |
| npm | every `node_modules` tree, nested and pnpm layouts, `.package-lock.json` integrity |
| Lockfiles | `requirements*.txt`, `uv.lock`, `poetry.lock`, `package-lock.json` |
| Docker | all local images (`docker image ls --all`), inspected with a Syft SBOM, never run |

Default roots are your home directory plus `/opt`, `/usr/lib`, `/usr/lib64`, `/usr/local`
and `/srv` (with `/Library/Frameworks/Python.framework` and `/opt/homebrew` on macOS).
When run as root it also covers every home under `/home` and `/Users`.

### Findings and severity

| Severity | Rule | Meaning |
| --- | --- | --- |
| critical | `malicious-package` | name + version matches a malicious OSV advisory (`MAL-`, CWE-506, malware advisories) or an IOC profile |
| critical | `ioc-hash` | a file or archive hash matches a known-bad hash, whatever version the package claims |
| critical | `ioc-file` | a file named in an IOC profile is installed (e.g. `litellm_init.pth`) |
| critical | `ioc-persistence` | a persistence path or dropped file exists (e.g. `~/.config/sysmon/sysmon.py`) |
| critical | `ioc-domain` | a supplied log mentions an IOC domain |
| high | `pth-exec` | a `.pth` file in site-packages runs code at interpreter start and is not allowlisted |
| info | `vulnerable-package` | ordinary known vulnerabilities (aliases collapsed) |

Each finding has its location and a recommended action. Critical findings that were not
in the previous scan of the same scope trigger `--alert-cmd` (findings as JSON on stdin)
and/or `--notify`.

## Configuration

`~/.config/supply-chain-sweep/config.toml` (or `--config FILE`, or `$SWEEP_CONFIG`):

```toml
[scan]
roots = ["~/work", "/data/envs"]   # added to the defaults
only_roots = false                 # true: use only these roots
exclude = ["~/huge-dataset"]
profile_dirs = ["~/security/profiles"]
logs = ["/var/log/dnsmasq.log"]
docker = true
caches = true
lockfiles = true
hash_archives = true               # sha256 of cached wheels/tarballs (cached between runs)

[intel]
feeds = ["PyPI", "npm"]

[[pth_allowlist]]
name = "my-company-hook.pth"       # fnmatch pattern
sha256 = "..."                     # optional: pin the exact content
contains = "import corp_bootstrap" # optional

[alert]
command = "/usr/local/bin/page-oncall"
```

Data (inventory history, hash cache, OSV mirror) lives in
`~/.local/share/supply-chain-sweep/` (`$SWEEP_HOME` overrides it).

## IOC profiles

Profiles are TOML files in `~/.config/supply-chain-sweep/profiles/` (or passed with
`--profile-file`). Put the top-level keys before any `[[packages]]` table:

```toml
id = "acme-incident-42"
name = "Compromised internal mirror"
references = ["https://wiki.example/incident-42"]
file_names = ["evil_init.pth"]
hashes = ["sha256:<hex>"]            # hex, algo:hex, or wheel RECORD base64
persistence_paths = ["~/.config/updater/run.py", "/tmp/.marker"]
domains = ["c2.example.net"]

[[packages]]
ecosystem = "PyPI"                   # or "npm"; PyPI profiles also match conda packages
name = "some-package"
versions = ["1.2.3"]                 # empty list = every version
```

A built-in profile covers the 2026 LiteLLM compromises (1.82.7, 1.82.8, 1.107.0). IOCs
that OSV advisories publish in `database_specific.iocs` (file hashes, dropped paths,
domains) are used automatically.

## Requirements coverage

| Req | Where |
| --- | --- |
| FR-1, FR-2 | `discovery.py`, `collectors/python.py`, `collectors/conda.py` |
| FR-3 | `collectors/caches.py` (pip, uv) |
| FR-4, NFR-2 | `collectors/docker.py` (Syft SBOM, images never run) |
| FR-5 | `collectors/npm.py`, npm cache in `collectors/caches.py` |
| FR-6 | `collectors/lockfiles.py` |
| FR-7 | `--root`, `--only-roots`, `--exclude`, `config.toml` |
| FR-8, FR-9, FR-10 | `models.Package`, `state.py` (SQLite inventory, diff vs previous scan) |
| FR-11, FR-12, FR-13, NFR-4, NFR-5 | `intel/osv.py`: local mirror of OSV exports, incremental refresh on each online run, `sweep update` on demand, offline scans |
| FR-14 | `intel/profiles.py` |
| FR-15 to FR-20 | `matching.py` |
| FR-21, FR-22 | `report.py` (text, JSON, SARIF 2.1.0) |
| FR-23 | exit code 1 on critical findings |
| FR-24 | `--profile`, `--path` |
| FR-25 | `sweep schedule`, `--alert-cmd`, `--notify` |
| NFR-1, NFR-3 | collectors read files only; `tests/test_scan.py::test_read_only` |
| NFR-6 | threaded collection, hash and SBOM caches |
| NFR-7 | Linux and macOS paths; Windows not targeted |
| NFR-8 | single package, optional Syft |
| NFR-9 | sorted output; `test_deterministic_output` |
| NFR-10 | unreadable or missing locations become warnings |

## Development

```sh
pip install -e '.[test]'
pytest
```
