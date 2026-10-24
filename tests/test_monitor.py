import json
import os
import socket
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from supply_chain_sweep.config import Config, MonitorConfig
from supply_chain_sweep.models import Severity
from supply_chain_sweep.monitor.capture import Tracker, dns_and_syn_filter
from supply_chain_sweep.monitor.daemon import Monitor, health
from supply_chain_sweep.monitor.detect import Detector, to_finding
from supply_chain_sweep.monitor.domains import Suffixes, lookalike
from supply_chain_sweep.monitor.enrich import RegistrationAge, match_indicator, parse_feed
from supply_chain_sweep.monitor.ingest import ingest_file, parse_dnsmasq
from supply_chain_sweep.monitor.packets import parse_dns, parse_ip, read_pcap
from supply_chain_sweep.monitor.procinfo import ProcessResolver, classify, container_id, env_for
from supply_chain_sweep.monitor.store import Event, MonitorStore
from tests.netutil import dns_query, dns_response, tcp_syn, udp, write_pcap

DAY = 86400
T0 = 1_790_000_000.0  # fixed clock for deterministic learning periods
PY = {"pid": 4242, "name": "python3", "exe": "/home/u/proj/.venv/bin/python3", "cmdline": "python app.py",
      "category": "interpreter", "env": "/home/u/proj/.venv"}
PIP = {"pid": 4243, "name": "pip", "exe": "/usr/bin/pip", "cmdline": "pip install foo", "category": "package_manager"}
CHROME = {"pid": 99, "name": "chrome", "exe": "/opt/google/chrome/chrome", "cmdline": "chrome --secret-url",
          "category": "browser"}


def dns(name, ts, proc, answers=()):
    return Event(ts, "dns", name, "A", "NOERROR", list(answers), process=dict(proc))


@pytest.fixture
def store(tmp_path):
    s = MonitorStore(tmp_path)
    yield s
    s.close()


def detector(store, indicators=None, rdap=None, **cfg):
    return Detector(store, MonitorConfig(**cfg), indicators or {"models.litellm.cloud": {"litellm-2026"}},
                    Suffixes(), rdap)


# --- packets -------------------------------------------------------------------------

def test_dns_parse_roundtrip():
    msg = parse_dns(dns_response("Files.PythonHosted.org", ["151.101.1.63", "2a04:4e42::319"], qid=7))
    assert (msg.id, msg.is_response, msg.name, msg.qtype) == (7, True, "files.pythonhosted.org", "A")
    assert msg.answers == ["151.101.1.63", "2a04:4e42::319"] and msg.ttl == 60
    q = parse_ip(udp("10.0.0.2", "8.8.8.8", 40000, 53, dns_query("pypi.org")))
    assert q.dns.name == "pypi.org" and not q.dns.is_response and q.sport == 40000


def test_dns_parse_rejects_loops():
    evil = bytearray(dns_query("a.b"))
    evil[12:14] = b"\xc0\x0c"  # pointer to itself
    with pytest.raises(ValueError):
        parse_dns(bytes(evil))
    assert parse_ip(udp("1.1.1.1", "2.2.2.2", 53, 1000, b"\x00" * 5)).dns is None  # garbage is ignored


def test_pcap_reader(tmp_path):
    pcap = tmp_path / "x.pcap"
    write_pcap(pcap, [(T0, udp("10.0.0.2", "8.8.8.8", 4000, 53, dns_query("evil.example"))),
                      (T0 + 0.01, udp("8.8.8.8", "10.0.0.2", 53, 4000, dns_response("evil.example", ["198.51.100.4"]))),
                      (T0 + 1, tcp_syn("10.0.0.2", "203.0.113.50", 5555, 443))])
    pkts = list(read_pcap(pcap))
    assert [p.dns.name if p.dns else p.dst for p in pkts] == ["evil.example", "evil.example", "203.0.113.50"]
    assert pkts[2].is_syn


def test_bpf_program_is_well_formed():
    prog = dns_and_syn_filter()
    assert 10 < len(prog) < 64
    for i, (op, jt, jf, _k) in enumerate(prog):
        if op & 0x07 == 0x05:  # BPF_JMP: both targets must land inside the program
            assert i + 1 + jt < len(prog) and i + 1 + jf < len(prog)
    assert prog[-1][0] == 0x06  # ends with a return


@pytest.mark.skipif(not hasattr(socket, "AF_PACKET") or os.geteuid() != 0, reason="needs root and AF_PACKET")
def test_live_capture_and_attribution_on_loopback():
    """Real kernel filter + /proc attribution: a query from this process is attributed to this pid."""
    import threading

    from supply_chain_sweep.monitor.capture import LinuxCapture, make_tracker

    # The filter only passes port 53, so serve on 127.0.0.54:53.
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.54", 53))
    except OSError:
        pytest.skip("port 53 busy")

    def serve():
        data, addr = srv.recvfrom(512)
        srv.sendto(dns_response("live.test.example", ["192.0.2.1"], qid=int.from_bytes(data[:2], "big")), addr)

    threading.Thread(target=serve, daemon=True).start()
    cap = LinuxCapture(["lo"])
    cap.open()
    tracker = make_tracker()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(2)
    client.sendto(dns_query("live.test.example", qid=99), ("127.0.0.54", 53))
    client.recv(512)
    events, t0 = [], time.time()
    for pkt in cap.packets(lambda: time.time() - t0 > 1.5 or events, lambda: None):
        events += tracker.feed(pkt)
    cap.close()
    client.close()
    srv.close()
    assert events and events[0].name == "live.test.example"
    assert events[0].process.get("pid") == os.getpid()
    assert events[0].process.get("category") == "interpreter"


# --- tracker ---------------------------------------------------------------------------

def test_tracker_pairs_and_direct_ip():
    attributed = []

    def resolve(proto, port, ip, netns=None):
        from supply_chain_sweep.monitor.procinfo import Process

        attributed.append((proto, port))
        return Process(pid=1, name="python3", category="interpreter")

    tr = Tracker(resolve=resolve, local_ips={"10.0.0.2"})
    feed = lambda raw, ts: tr.feed(parse_ip(raw, ts))
    assert feed(udp("10.0.0.2", "8.8.8.8", 4000, 53, dns_query("pkg.example", qid=5)), T0) == []
    # The same query leaving through NAT (new source) is not counted twice.
    assert feed(udp("192.168.1.9", "8.8.8.8", 61000, 53, dns_query("pkg.example", qid=5)), T0 + 0.001) == []
    evs = feed(udp("8.8.8.8", "10.0.0.2", 53, 4000, dns_response("pkg.example", ["198.51.100.7"], qid=5)), T0 + 0.02)
    assert [(e.kind, e.name, e.answers) for e in evs] == [("dns", "pkg.example", ["198.51.100.7"])]
    assert evs[0].process["category"] == "interpreter"
    assert feed(tcp_syn("10.0.0.2", "198.51.100.7", 5000, 443), T0 + 1) == []  # resolved first: no event
    evs = feed(tcp_syn("10.0.0.2", "203.0.113.9", 5001, 443), T0 + 1)
    assert [(e.kind, e.dst_ip, e.dst_port) for e in evs] == [("conn", "203.0.113.9", 443)]
    feed(udp("10.0.0.2", "8.8.8.8", 4001, 53, dns_query("silent.example", qid=6)), T0 + 2)
    late = tr.expire(T0 + 10)
    assert [(e.name, e.rcode) for e in late] == [("silent.example", "NORESPONSE")]


# --- process attribution ---------------------------------------------------------------

@pytest.mark.parametrize("name,exe,argv,expected", [
    ("python3.12", "/usr/bin/python3.12", ["python3", "app.py"], "interpreter"),
    ("python3", "/usr/bin/python3.12", ["python3", "-m", "pip", "install", "x"], "package_manager"),
    ("node", "/usr/bin/node", ["node", "/usr/lib/node_modules/npm/bin/npm-cli.js", "install"], "package_manager"),
    ("node", "/usr/bin/node", ["node", "server.js"], "interpreter"),
    ("uv", "/home/u/.local/bin/uv", ["uv", "sync"], "package_manager"),
    ("chrome", "/opt/google/chrome/chrome", ["chrome"], "browser"),
    ("Google Chrome He", "/Applications/Google Chrome.app/Contents/x", [], "browser"),
    ("dockerd", "/usr/bin/dockerd", ["dockerd"], "container"),
    ("curl", "/usr/bin/curl", ["curl", "x"], "other"),
])
def test_classify(name, exe, argv, expected):
    assert classify(name, exe, argv) == expected


def test_env_and_container_detection(tmp_path):
    venv = tmp_path / "proj" / ".venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home=/usr\n")
    assert env_for(str(venv / "bin" / "python3")) == str(venv)
    # venv python is a symlink: /proc/<pid>/exe is the base interpreter, argv[0] is the venv path
    assert env_for("/usr/bin/python3.12", argv0=str(venv / "bin" / "python")) == str(venv)
    assert env_for("/usr/bin/python3.12", cwd=str(tmp_path / "proj"), argv0=".venv/bin/python") == str(venv)
    assert env_for("/usr/bin/python3", environ={"CONDA_PREFIX": "/opt/conda/envs/ml"}) == "/opt/conda/envs/ml"
    (tmp_path / "web" / "node_modules").mkdir(parents=True)
    assert env_for("/usr/bin/node", cwd=str(tmp_path / "web" / "src")) == str(tmp_path / "web")
    cid = "a" * 64
    assert container_id(f"0::/system.slice/docker-{cid}.scope\n") == cid
    assert container_id("0::/user.slice\n") == ""


@pytest.mark.skipif(not os.path.exists("/proc/self/fd"), reason="Linux /proc only")
def test_process_resolver_finds_own_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    try:
        proc = ProcessResolver().resolve("udp", s.getsockname()[1], "127.0.0.1")
        assert proc is not None and proc.pid == os.getpid()
        assert proc.category == "interpreter" and "python" in proc.exe
    finally:
        s.close()


# --- domains ---------------------------------------------------------------------------------

def test_registered_domain():
    fallback = Suffixes()
    assert fallback.registered("a.b.example.co.uk") == "example.co.uk"
    assert fallback.registered("files.pythonhosted.org") == "pythonhosted.org"
    assert fallback.registered("evil.github.io") == "evil.github.io"
    psl = Suffixes("// x\ncom\n*.ck\n!www.ck\n")
    assert psl.registered("a.b.foo.ck") == "b.foo.ck"
    assert psl.registered("www.ck") == "www.ck"
    assert psl.registered("10.0.0.1") == "10.0.0.1"


@pytest.mark.parametrize("name,flagged", [
    ("models.litellm.cloud", True), ("pypi-mirror.com", True), ("githab.com", True),
    ("files.pythonhosted.org.attacker.net", True), ("anthropic-api.co", True),
    ("pypi.org", False), ("files.pythonhosted.org", False), ("api.github.com", False), ("example.com", False),
    ("litellm.ai", False), ("pythonhosted.org", False),
])
def test_lookalike(name, flagged):
    s = Suffixes()
    assert bool(lookalike(name, s.registered(name))) is flagged


def test_indicator_matching_and_feeds():
    ind = {"litellm.cloud": {"MAL-1"}, "203.0.113.7": {"p"}}
    assert match_indicator("models.litellm.cloud.", ind) == ("litellm.cloud", {"MAL-1"})
    assert match_indicator("notlitellm.cloud", ind) is None
    assert match_indicator("203.0.113.7", ind)
    assert parse_feed("# c\n0.0.0.0 bad.example\n127.0.0.1 localhost\n", "hosts") == {"bad.example"}
    assert parse_feed("||evil.example^\n198.51.100.1\nnot a domain!\n", "domains") == {"evil.example", "198.51.100.1"}


# --- detection --------------------------------------------------------------------------------

def test_threat_feed_hit_is_critical_for_any_category(store):
    det = detector(store)
    f = det.handle(dns("models.litellm.cloud", T0, PY, ["198.51.100.1"]))
    assert f["severity"] == "critical" and f["data"]["signals"][0]["signal"] == "threat_feed"
    fb = det.handle(dns("models.litellm.cloud", T0, CHROME))
    assert fb["severity"] == "critical"  # MON-17: browsers are still checked against threat feeds
    finding = to_finding(f)
    # MON-21: domain, ips, process, command line, environment, signals, timestamp
    d = finding.details
    assert d["domain"] == "litellm.cloud" and d["ips"] == ["198.51.100.1"]
    assert d["process"]["cmdline"] == "python app.py" and d["env"] == "/home/u/proj/.venv"
    assert d["signals"] and d["first_seen"].startswith("2026-")
    assert finding.rule == "network-threat" and finding.advisory == "litellm-2026"


def test_answer_ip_indicator(store):
    det = detector(store, indicators={"203.0.113.7": {"prof"}})
    assert det.handle(dns("innocent.example", T0, PY, ["203.0.113.7"]))["severity"] == "critical"


def test_learning_then_baseline(store):
    det = detector(store, learning_days=7)
    assert det.handle(dns("api.internal-tool.dev", T0, PY)) is None  # learned
    assert det.handle(dns("api.internal-tool.dev", T0 + 8 * DAY, PY)) is None  # in baseline afterwards
    f = det.handle(dns("telemetry.unknown-thing.xyz", T0 + 8 * DAY, PY))
    assert f["severity"] == "medium"
    assert {s["signal"] for s in f["data"]["signals"]} == {"first_seen", "out_of_baseline"}
    # Browsers are excluded from baseline / first-seen alerts.
    assert det.handle(dns("some-news-site.example", T0 + 8 * DAY, CHROME)) is None
    # Defaults are allowed without learning.
    assert det.handle(dns("files.pythonhosted.org", T0 + 8 * DAY, PIP)) is None


def test_lookalike_new_domain_from_interpreter_is_critical(store):
    det = detector(store, learning_days=0)
    f = det.handle(dns("pypi-files.net", T0, PIP))
    assert f["severity"] == "critical"
    assert {"lookalike", "first_seen"} <= {s["signal"] for s in f["data"]["signals"]}


def test_newly_registered_via_rdap(store):
    asked = []
    created = (datetime.fromtimestamp(T0, UTC) - timedelta(days=5)).isoformat()

    def opener(url):
        asked.append(url)
        return json.dumps({"events": [{"eventAction": "registration", "eventDate": created}]}).encode()

    det = detector(store, rdap=RegistrationAge(store, opener=opener), learning_days=0)
    f = det.handle(dns("cdn.fresh-domain.xyz", T0, PY))
    assert "newly_registered" in {s["signal"] for s in f["data"]["signals"]}
    assert f["severity"] == "high"
    # MON-NFR-2: only the registered domain is sent, once (then cached).
    det.handle(dns("api.fresh-domain.xyz", T0 + 1, PY))
    assert asked == ["https://rdap.org/domain/fresh-domain.xyz"]
    # Allowlisted domains are never looked up.
    det.handle(dns("pypi.org", T0, PY))
    assert len(asked) == 1


def test_direct_ip_and_metadata(store):
    det = detector(store, learning_days=0)
    # (TEST-NET ranges count as private in Python, so use a real public address.)
    f = det.handle(Event(T0, "conn", dst_ip="45.33.32.156", dst_port=4444, process=dict(PY)))
    assert f["data"]["signals"][0]["signal"] == "direct_ip" and f["severity"] == "low"
    assert det.handle(Event(T0, "conn", dst_ip="192.168.1.10", dst_port=22, process=dict(PY))) is None
    m = det.handle(Event(T0, "conn", dst_ip="169.254.169.254", dst_port=80, process=dict(PY)))
    assert m["data"]["signals"][0]["signal"] == "cloud_metadata" and m["severity"] == "medium"


def test_aggregation_and_benign(store):
    det = detector(store, learning_days=0)
    for i in range(5):
        f = det.handle(dns(f"x{i}.weird-service.xyz", T0 + i, PY))
    rows = store.findings()
    assert len(rows) == 1 and rows[0]["count"] == 5 and len(f["data"]["names"]) == 5
    store.allow("interpreter", "weird-service.xyz", "user")
    det.invalidate_allowlist()
    assert det.handle(dns("x9.weird-service.xyz", T0 + 10, PY)) is None
    assert det.handle(dns("x9.weird-service.xyz", T0 + 10, PIP)) is not None  # other category still flagged


def test_browser_events_are_domain_only(store):
    det = detector(store)
    det.handle(dns("news.example", T0, CHROME, ["192.0.2.1"]))
    row = store.conn.execute("SELECT process, answers FROM events").fetchone()
    assert json.loads(row[0]) == {"category": "browser", "name": "chrome"}
    assert json.loads(row[1]) == []


def test_retroactive_ioc_search(store):
    det = detector(store, indicators={}, learning_days=30)
    det.handle(dns("beacon.later-bad.example", T0, PY))
    assert det.retro_check() == []
    det.indicators = {"later-bad.example": {"new-profile"}}
    hits = det.retro_check()
    assert len(hits) == 1 and hits[0]["severity"] == "critical" and hits[0]["data"]["retroactive"]
    assert det.retro_check() == []  # already checked


def test_retention(store):
    det = detector(store)
    det.handle(dns("old.example", time.time() - 40 * DAY, PY))
    det.handle(dns("new.example", time.time(), PY))
    assert store.prune(30) == 1


# --- ingest ------------------------------------------------------------------------------------

def test_ingest_formats(tmp_path):
    lines = [
        "Oct 24 08:00:01 dnsmasq[123]: query[A] models.litellm.cloud from 192.168.1.20",
        "Oct 24 08:00:01 dnsmasq[123]: forwarded models.litellm.cloud to 1.1.1.1",
        "Oct 24 08:00:01 dnsmasq[123]: reply models.litellm.cloud is 198.51.100.3",
        "Oct 24 08:00:02 dnsmasq[123]: query[AAAA] gone.example from 192.168.1.20",
        "Oct 24 08:00:02 dnsmasq[123]: reply gone.example is NXDOMAIN",
    ]
    evs = list(parse_dnsmasq(lines, year=2026))
    assert [(e.name, e.answers, e.rcode) for e in evs] == [("models.litellm.cloud", ["198.51.100.3"], "NOERROR"),
                                                           ("gone.example", [], "NXDOMAIN")]
    assert evs[0].process == {"name": "192.168.1.20", "category": "unknown"}
    csvf = tmp_path / "nextdns.csv"
    csvf.write_text("timestamp,domain,query_type,dnssec,protocol,client_ip,status,reasons,destination_country,"
                    "root_domain,device_id,device_name,device_model,client_name\n"
                    "2026-10-24T08:00:00.000Z,pypi.org,A,false,DNS-over-HTTPS,1.2.3.4,default,,US,pypi.org,"
                    "ABC,laptop,mac,\n")
    assert [(e.name, e.process["name"]) for e in ingest_file(csvf)] == [("pypi.org", "laptop")]
    jl = tmp_path / "e.jsonl"
    jl.write_text(json.dumps({"ts": T0, "name": "a.example", "process": PY}) + "\n")
    assert [e.process["category"] for e in ingest_file(jl)] == ["interpreter"]
    pcap = tmp_path / "c.pcap"
    write_pcap(pcap, [(T0, udp("10.0.0.2", "8.8.8.8", 4000, 53, dns_query("p.example"))),
                      (T0, udp("8.8.8.8", "10.0.0.2", 53, 4000, dns_response("p.example", ["192.0.2.9"])))])
    assert [(e.name, e.source) for e in ingest_file(pcap, category="interpreter")] == [("p.example", "pcap")]


# --- daemon: inventory link, targeted scan, alerts, digest, health ----------------------------

@pytest.fixture
def monitor(tmp_path, monkeypatch):
    for v in ("SWEEP_HOME", "SUDO_USER"):
        monkeypatch.delenv(v, raising=False)
    cfg = Config(roots=[], profile_dirs=[], docker=False, data_dir=tmp_path / "data")
    out = tmp_path / "alerts.jsonl"
    cfg.monitor = MonitorConfig(learning_days=0, rdap=False, notify=False, psl_download=False,
                                alert_command=f"sh -c 'cat >> {out}; echo >> {out}'", max_alerts_per_day=2)
    scans = []
    mon = Monitor(cfg, scan_runner=lambda c, env: scans.append(env) or {"critical": 1, "findings": ["x"]})
    mon.alerts_file, mon.scans = out, scans
    yield mon
    mon.close()


def test_monitor_links_inventory_and_rescans(monitor, tmp_path):
    from supply_chain_sweep.models import Ecosystem, Package, SourceType
    from supply_chain_sweep.state import State

    env = tmp_path / "proj" / ".venv"
    env.mkdir(parents=True)
    st = State(monitor.cfg.data_dir)
    pkg = Package(Ecosystem.PYPI, "litellm", "1.82.8", SourceType.ENVIRONMENT, str(env / "x.dist-info"), str(env))
    st.save_scan("full", "2026-10-24T00:00:00+00:00", [pkg], [], {})
    st.close()
    proc = {**PY, "env": str(env)}
    monitor.process([dns("models.litellm.cloud", time.time(), proc)])
    monitor.wait_for_scans()
    row = monitor.store.findings()[0]
    assert row["data"]["inventory"]["packages"] == 1  # MON-24
    assert monitor.scans == [str(env)]  # MON-26
    assert row["data"]["targeted_scan"]["critical"] == 1
    alert = json.loads(monitor.alerts_file.read_text().splitlines()[0])
    assert alert["finding"]["severity"] == "critical"  # MON-19


def test_alert_cap_spares_threat_hits(monitor):
    for i in range(4):
        monitor.process([dns(f"pypi-evil{i}.net", time.time(), PIP)])  # lookalike + first seen: critical
    monitor.process([dns("models.litellm.cloud", time.time(), PIP)])  # threat feed: always alerts
    lines = [ln for ln in monitor.alerts_file.read_text().splitlines() if ln.strip()]
    assert len(lines) == 3  # cap of 2, plus the threat-feed hit


def test_digest_written_once_a_day(monitor):
    monitor.process([dns("odd.unknown-host.xyz", time.time(), PY)])
    noon = datetime.now().replace(hour=12).timestamp()
    path = monitor.maybe_digest(noon)
    assert path and "odd.unknown-host.xyz" in Path(path).read_text()
    assert monitor.maybe_digest(noon + 60) is None


def test_health_detects_unclean_stop(store):
    assert health(store)["state"] == "never-run"
    store.set_meta("heartbeat", {"ts": time.time(), "started": time.time() - 100, "dns": 3,
                                 "last_dns_ts": time.time()})
    store.set_meta("expected_running", True)
    assert health(store)["state"] == "running"
    store.set_meta("heartbeat", {"ts": time.time() - 3600, "started": time.time() - 7200})
    st = health(store)
    assert st["state"] == "stopped-unexpectedly" and st["issues"]
    store.set_meta("expected_running", False)
    assert health(store)["state"] == "stopped"
    store.set_meta("heartbeat", {"ts": time.time(), "started": time.time() - 3 * DAY, "last_dns_ts": time.time() - 2 * DAY})
    store.set_meta("expected_running", True)
    assert any("capture may be disabled" in i for i in health(store)["issues"])


# --- CLI ---------------------------------------------------------------------------------------

def test_cli_ingest_benign_and_combined_report(tmp_path, monkeypatch, capsys):
    from supply_chain_sweep.cli import main

    monkeypatch.setenv("SWEEP_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("SWEEP_CONFIG", str(tmp_path / "cfg.toml"))
    (tmp_path / "cfg.toml").write_text("[monitor]\nrdap = false\nnotify = false\npsl_download = false\n"
                                       "learning_days = 0\n")
    log = tmp_path / "dns.jsonl"
    log.write_text("\n".join(json.dumps({"ts": time.time(), "name": n, "process": PY})
                             for n in ("models.litellm.cloud", "api.strange-thing.xyz")) + "\n")
    assert main(["monitor", "ingest", str(log)]) == 1
    capsys.readouterr()
    out = tmp_path / "f.json"
    main(["monitor", "findings", "--json", str(out)])
    ids = {f["details"]["domain"]: f["details"]["id"] for f in json.loads(out.read_text())["findings"]}
    assert main(["monitor", "benign", ids["strange-thing.xyz"]]) == 0
    main(["monitor", "allow", "list"])
    assert "strange-thing.xyz" in capsys.readouterr().out
    sarif = tmp_path / "r.sarif"
    assert main(["report", "--sarif", str(sarif)]) == 1
    results = json.loads(sarif.read_text())["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["network-threat"]
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "dns:models.litellm.cloud"


def test_severity_ordering_includes_monitor_levels():
    assert [s.rank for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)] == \
        [0, 1, 2, 3, 4]


# --- eBPF attribution ---------------------------------------------------------------------------

def test_kernel_attributor_parsing_and_lookup():
    import io
    import types

    from supply_chain_sweep.monitor.ebpf import KernelAttributor

    ka = KernelAttributor(bpftrace="/bin/false")
    ka._offset = 0.0
    ka.proc = types.SimpleNamespace(stdout=io.StringIO(
        "Attaching 3 probes...\n"
        "U 1000000000000 501 500 127.0.0.53 python3\n"
        "U 1000400000000 777 1 127.0.0.53 curl\n"
        "T 1000500000000 888 1 45.33.32.156:4444 node\n"
        "garbage line\n"))
    ka._read()
    assert ka.lookup("udp", "127.0.0.53", 53, 1000.01) == (501, 500, "python3")
    assert ka.lookup("udp", "127.0.0.53", 53, 1000.41) == (777, 1, "curl")
    assert ka.lookup("udp", "127.0.0.53", 53, 1003.0) is None  # too long after the send
    assert ka.lookup("tcp", "45.33.32.156", 4444, 1000.5) == (888, 1, "node")
    assert ka.lookup("udp", "8.8.8.8", 53, 1000.0) is None


def test_tracker_waits_for_kernel_attribution():
    found = {}
    tr = Tracker(resolve=lambda *a: None, kernel_lookup=lambda proto, ip, port, ts: found.get((proto, ip)))
    tr.feed(parse_ip(udp("127.0.0.1", "127.0.0.53", 4000, 53, dns_query("k.example", qid=3)), T0))
    out = tr.feed(parse_ip(udp("127.0.0.53", "127.0.0.1", 53, 4000, dns_response("k.example", [], qid=3)), T0))
    assert out == [] and len(tr.held) == 1  # held while the kernel side catches up
    found[("udp", "127.0.0.53")] = {"pid": 7, "name": "pip", "category": "package_manager"}
    ev = tr.poll(T0 + 0.1)
    assert [e.process["pid"] for e in ev] == [7]
    tr.feed(parse_ip(udp("127.0.0.1", "8.8.8.8", 4001, 53, dns_query("u.example", qid=4)), T0))
    tr.feed(parse_ip(udp("8.8.8.8", "127.0.0.1", 53, 4001, dns_response("u.example", [], qid=4)), T0))
    assert tr.poll(T0 + 0.1) == []
    assert [e.category for e in tr.poll(T0 + 1)] == ["unknown"]  # gave up after the grace period


@pytest.mark.skipif(not __import__("supply_chain_sweep.monitor.ebpf", fromlist=["x"]).KernelAttributor.available(),
                    reason="needs root and bpftrace")
def test_live_ebpf_attribution():
    import subprocess
    import sys

    from supply_chain_sweep.monitor.ebpf import KernelAttributor

    ka = KernelAttributor()
    if not ka.start():
        pytest.skip(f"bpftrace cannot attach here: {ka.error}")
    try:
        # A short-lived child sends one DNS-port datagram and exits immediately.
        child = subprocess.run([sys.executable, "-c",
                                "import socket,os;s=socket.socket(2,2);s.sendto(b'x'*12,('127.0.0.77',53));"
                                "print(os.getpid())"], capture_output=True, text=True, check=True)
        pid = int(child.stdout)
        deadline = time.time() + 3
        hit = None
        while time.time() < deadline and not hit:
            hit = ka.lookup("udp", "127.0.0.77", 53, time.time())
            time.sleep(0.05)
        assert hit and hit[0] == pid and hit[2].startswith("python")
    finally:
        ka.stop()


def test_tcpdump_line_parser():
    """macOS backend (experimental): standard tcpdump DNS output plus pktap process metadata."""
    from supply_chain_sweep.monitor.capture import parse_tcpdump_line

    pending = {}
    q = ("12:00:00.000001 (en0, proc python3.12:4321:abcd, svc BE, out) IP 192.168.1.5.53000 > "
         "192.168.1.1.53: 4660+ A? models.litellm.cloud. (38)")
    r = ("12:00:00.020000 (en0, proc mDNSResponder:100:ef, svc BE, in) IP 192.168.1.1.53 > 192.168.1.5.53000: "
         "4660 1/0/0 A 198.51.100.1 (54)")
    assert parse_tcpdump_line(q, pending) is None
    ev = parse_tcpdump_line(r, pending)
    assert (ev.name, ev.answers, ev.process["pid"], ev.process["category"]) == \
        ("models.litellm.cloud", ["198.51.100.1"], 4321, "interpreter")


def test_scan_survives_read_only_monitor_db(cfg, tmp_path, monkeypatch, capsys):
    """A user's `sweep update`/`scan` must not fail on the service's read-only monitor.db."""
    import sqlite3

    from supply_chain_sweep import cli

    def boom(*_a, **_k):
        raise sqlite3.OperationalError("attempt to write a readonly database")

    monkeypatch.setattr("supply_chain_sweep.monitor.cli.retro_after_update", boom)
    cli._retro(cfg)
    assert "skipped network monitor history check" in capsys.readouterr().err
