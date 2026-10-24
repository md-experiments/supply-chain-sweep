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

## Network monitor

The scanner finds malicious packages at rest; the monitor catches them when they call
home. It records DNS lookups and direct-IP connections, attributes each one to a
process, and flags the ones a package manager, interpreter or container should not make.
Detection is per process: browsers are noisy, but `pip`, `npm`, `python` and containers
contact a small, predictable set of domains.

```sh
sudo sweep monitor run                 # foreground (Linux: needs root / CAP_NET_RAW)
sudo sweep monitor install --yes --notify-user "$USER"   # systemd service (launchd on macOS)
sweep monitor status                   # running? capture healthy? CPU / memory?
sweep monitor findings [--json F] [--sarif F]
sweep monitor benign <id>              # mark benign: allowlists the domain for that category
sweep monitor allow list|add|remove example.com [--category interpreter]
sweep monitor digest                   # medium/low findings from the last 24 h
sweep monitor ingest dnsmasq.log nextdns.csv capture.pcap   # resolver logs instead of capture
sweep monitor retro                    # search stored DNS history for new IOC domains
sweep report [--json F] [--sarif F]    # scanner + monitor findings in one report
```

### How it captures

- **Linux:** an `AF_PACKET` socket with a kernel BPF filter. Only DNS packets (UDP
  port 53) and the headers of outgoing TCP SYNs reach user space: other traffic and
  payloads are never copied. The socket only observes, so it adds no DNS latency.
- **Process attribution:** with `bpftrace` installed (the default `attribution = "auto"`),
  syscall tracepoints (`connect`/`sendto` to port 53, `inet_sock_set_state`) record
  the pid, parent and command of each DNS client and TCP connection as it happens.
  Without it, sockets are looked up in `/proc`. That works against slow resolvers, but
  misses many lookups answered by a local caching resolver (systemd-resolved), whose
  clients close their socket within a millisecond.
- **Categories:** package manager (pip, uv, conda, npm, `python -m pip`, `node npm-cli.js`, ...),
  interpreter, container, browser, other. A tool run by pip or python (a `curl` in an
  install hook) counts as its parent. Interpreters are linked to their venv or conda env,
  and container traffic to the container and image name.
- **macOS (experimental, untested):** Apple's `tcpdump -k NP -i pktap,all`, which labels
  packets with the sending process.
- **No capture:** `sweep monitor ingest` reads dnsmasq/Pi-hole logs, NextDNS CSV
  exports, JSON lines or pcap files.

### Signals and scoring

| Signal | Weight | Applies to |
| --- | --- | --- |
| threat feed / IOC profile (domain, parent domain, answer IP or destination IP) | 100 (always critical) | every category, browsers included |
| cloud metadata endpoint (169.254.169.254, ...) | 50 | non-browser |
| lookalike of a vendor or registry (`litellm.cloud` vs `litellm.ai`, `pypi-files.net`, `githab.com`) | 40 | non-browser |
| registered within 30 days (RDAP) | 40 | non-browser, only for domains that already look unusual |
| direct-IP connection | 30 | package managers, interpreters, containers |
| outside the learned baseline | 25 | package managers, interpreters, containers |
| first seen on this host | 15 | non-browser |

Scores map to critical (90+), high (60+), medium (35+) and low (15+). An interpreter or
package manager contacting a new lookalike domain is always critical. Events from
`other`/unknown processes count at 60%. Repeated events for the same domain, category
and environment are combined into one finding with a count.

During the first 7 days (`learning_days`) the monitor learns the domains each category
normally uses. A default allowlist covers the registries and APIs developers use (PyPI,
npm, conda, GitHub, Docker registries, the major LLM APIs, ...).

### Alerts and reports

- Critical findings raise a desktop notification and run `[monitor] alert_command` (with the
  finding as JSON on stdin). At most 5 alerts a day (`max_alerts_per_day`); threat-feed
  hits are never suppressed.
- Medium and low findings go into a daily digest (`digests/YYYY-MM-DD.txt`, `sweep monitor digest`).
- Each finding lists the domain, IPs, process, command line, environment or container,
  signals and timestamps. It is linked to the scanner's inventory for that environment,
  and a critical finding starts a targeted `sweep scan --path <env>`.
- When `sweep update` or `sweep scan` brings new IOC domains, stored DNS history is
  searched for them (the daemon also does this hourly).

### Privacy and safety

- Everything stays in `monitor.db` on the machine. Raw events are kept for 30 days
  (`retention_days`); findings are kept until marked benign or dismissed.
- Browser events are stored as domain-only records, with no command line or answers.
- External services get one registered domain per request: RDAP for registration age
  (`rdap = false` turns it off) and optional threat feeds, which are downloaded
  whole. The Public Suffix List is downloaded once a month (`psl_download = false`).
- The service drops every capability except those listed in `sweep monitor install --help`.
  Only the notify user's group can read its data dir.
- Tampering: the daemon writes a heartbeat. `sweep monitor status` and `sweep report`
  report a monitor that stopped without a clean shutdown, and capture that has gone quiet
  for 24 h; the gap is also alerted at the next start.

Measured on Linux (kernel 6.18), idle with light traffic: 0.14% CPU in total. The daemon
itself uses 45 MB RSS. With the eBPF helper, total RSS is 138 MB, but only 59 MB of it is
private memory: most of bpftrace's 95 MB RSS is shared LLVM library code. With
`attribution = "proc"` the total is about 45 MB.

```toml
[monitor]
learning_days = 7
new_domain_days = 30
retention_days = 30
rdap = true
attribution = "auto"            # auto | ebpf | proc
max_alerts_per_day = 5
digest_hour = 9
alert_command = "/usr/local/bin/page-oncall"
threat_feeds = [{ name = "my-feed", url = "https://example.org/hosts.txt", format = "hosts" }]
allow = [{ domain = "telemetry.mycorp.dev", category = "interpreter" }]
brands = { mycorp = ["mycorp.com"] }   # extra lookalike targets
```

IOC profiles can list `ips = [...]` next to `domains` for the monitor.

### Monitor requirements coverage

| Req | Where |
| --- | --- |
| MON-1, MON-3, MON-NFR-5, MON-NFR-7 | `monitor/capture.py` (AF_PACKET + BPF filter; TCP direct-IP only, not UDP) |
| MON-2 | `monitor/procinfo.py` `ContainerMap`, cgroup detection (unit-tested; no Docker daemon in CI) |
| MON-4 | `monitor/ingest.py` |
| MON-5, MON-6, MON-7 | `monitor/procinfo.py`, `monitor/ebpf.py` |
| MON-8 to MON-13 | `monitor/detect.py`, `monitor/domains.py`, `monitor/enrich.py` |
| MON-14 to MON-18 | `monitor/detect.py` (learning, defaults, per-category allowlist), `sweep monitor allow` |
| MON-19, MON-20 | `monitor/daemon.py` `Notifier`, `maybe_digest` |
| MON-21, MON-22, MON-27 | `detect.to_finding`, scanner JSON/SARIF, `sweep report` |
| MON-23 | `sweep monitor benign` |
| MON-24, MON-25, MON-26 | `Monitor.inventory_link`, `Detector.retro_check`, targeted scan |
| MON-NFR-1 to MON-NFR-4 | `monitor/store.py`, `monitor/enrich.py` |
| MON-NFR-6 | measured above; `sweep monitor status` flags a breach of the budget |
| MON-NFR-8, MON-NFR-9 | `monitor/service.py` (systemd `Restart=always`, launchd `KeepAlive`, minimal capabilities) |
| MON-NFR-10 | Linux; macOS experimental |
| MON-NFR-11 | `daemon.health`, `report_unclean_stop` |
| MON-NFR-12 | daily alert cap, learning period, aggregated findings |

## Development

```sh
pip install -e '.[test]'
pytest
```
