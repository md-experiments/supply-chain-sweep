"""Process attribution on Linux via /proc (MON-5, MON-6, MON-7).

A packet's local port is looked up in /proc/net/{udp,tcp}[6] to find the socket
inode, and the inode is mapped to the process that holds it via /proc/<pid>/fd.
Reading other users' fd tables needs root or CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH;
without them, attribution is best effort and unknown processes are reported as such.
"""

from __future__ import annotations

import ipaddress
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

PACKAGE_MANAGERS = {"pip", "pip3", "uv", "uvx", "conda", "mamba", "micromamba", "poetry", "pipx", "pdm", "hatch",
                    "pipenv", "npm", "npx", "pnpm", "yarn", "corepack"}
INTERPRETERS = {"python", "python3", "pythonw", "node", "nodejs", "deno", "bun", "pypy", "pypy3"}
BROWSERS = {"chrome", "google-chrome", "chromium", "chromium-browser", "firefox", "firefox-bin", "firefox-esr",
            "brave", "brave-browser", "msedge", "microsoft-edge", "opera", "vivaldi", "safari",
            "google chrome helper", "google chrome", "com.apple.webkit.networking", "arc", "epiphany"}
CONTAINER_DAEMONS = {"dockerd", "containerd", "docker-proxy", "buildkitd", "containerd-shim", "containerd-shim-runc-v2",
                     "podman", "conmon"}
# Script names that make `python x` / `node x` a package manager.
_PM_SCRIPTS = re.compile(r"(?:^|/)(npm-cli\.js|npx-cli\.js|yarn(?:\.js|\.cjs)?|pnpm(?:\.cjs)?|pip\d?(?:\.\d+)?|uv|"
                         r"conda|poetry|pipx|pdm)$")
_VERSIONED = re.compile(r"^(python|pip|pypy)\d+(\.\d+)*$")
_CONTAINER_ID = re.compile(r"(?:docker[-/]|containerd[-/]|libpod-|cri-containerd-)([0-9a-f]{64})")

CATEGORIES = ("package_manager", "interpreter", "container", "browser", "other", "unknown")


@dataclass
class Process:
    pid: int = 0
    name: str = ""
    exe: str = ""
    cmdline: str = ""
    ppid: int = 0
    parent: str = ""  # parent exe
    category: str = "unknown"
    via: str = ""  # set when the category comes from an ancestor (e.g. curl run by pip)
    env: str = ""  # venv / conda env / node project root
    container: str = ""
    image: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in ("", 0)}


def base_name(path_or_name: str) -> str:
    n = os.path.basename(path_or_name).lower()
    if _VERSIONED.match(n):
        n = re.sub(r"\d.*$", "", n) or n
        n = {"python": "python", "pip": "pip", "pypy": "pypy"}.get(n, n)
    return n.removesuffix(".exe")


def classify(name: str, exe: str, argv: list[str], container: str = "") -> str:
    """Category from the process itself (MON-6)."""
    if container:
        return "container"
    names = {base_name(name), base_name(exe)}
    if names & CONTAINER_DAEMONS:
        return "container"
    if names & BROWSERS or any(b in exe.lower() for b in ("/google chrome", "/firefox", "/chromium", "/safari")):
        return "browser"
    if names & PACKAGE_MANAGERS:
        return "package_manager"
    if names & INTERPRETERS or any(n.startswith(("python", "node")) for n in names):
        script = next((a for a in argv[1:] if not a.startswith("-")), "")
        if "-m" in argv[1:3]:
            module = argv[argv.index("-m") + 1] if argv.index("-m") + 1 < len(argv) else ""
            if module in PACKAGE_MANAGERS:
                return "package_manager"
        if script and _PM_SCRIPTS.search(script):
            return "package_manager"
        return "interpreter"
    return "other"


def env_for(exe: str, cwd: str = "", environ: dict[str, str] | None = None, category: str = "",
            argv0: str = "") -> str:
    """Environment root for an interpreter: venv, conda env, or node project (MON-7).

    `argv0` matters for venvs: their bin/python is a symlink, so /proc/<pid>/exe names the base interpreter.
    """
    environ = environ or {}
    for var in ("VIRTUAL_ENV", "CONDA_PREFIX"):
        if environ.get(var):
            return environ[var]
    candidates = []
    if argv0 and "/" in argv0:
        candidates.append(Path(cwd, argv0) if cwd and not argv0.startswith("/") else Path(argv0))
    candidates.append(Path(exe))
    for p in candidates:
        for cand in list(p.parents)[:4]:
            if (cand / "pyvenv.cfg").exists() or (cand / "conda-meta").is_dir():
                return str(cand)
    if cwd and base_name(exe) in ("node", "nodejs", "bun", "deno", "npm", "npx", "pnpm", "yarn"):
        d = Path(cwd)
        for cand in [d, *d.parents][:8]:
            if (cand / "node_modules").is_dir():
                return str(cand)
    return ""


def container_id(cgroup_text: str) -> str:
    m = _CONTAINER_ID.search(cgroup_text)
    return m.group(1) if m else ""


# --- /proc access -----------------------------------------------------------

def _read(path: str, limit: int = 65536) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


def _hex_addr(text: str) -> tuple[str, int]:
    addr, port = text.split(":")
    raw = bytes.fromhex(addr)
    if len(raw) == 4:
        ip = str(ipaddress.IPv4Address(raw[::-1]))
    else:  # four little-endian 32-bit words
        ip = str(ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))))
    return ip, int(port, 16)


def socket_inodes(proto: str, port: int, root: str = "/proc", ip: str = "") -> list[int]:
    """Inodes of sockets bound to a local port, from /proc/net/{udp,tcp}[6]."""
    out = []
    for table in (proto, proto + "6"):
        text = _read(f"{root}/net/{table}", 4 << 20).decode("ascii", "replace")
        for line in text.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 10:
                continue
            try:
                lip, lport = _hex_addr(cols[1])
            except ValueError:
                continue
            if lport == port and (not ip or lip in (ip, "0.0.0.0", "::") or lip.endswith(ip)):
                inode = int(cols[9])
                if inode:
                    out.append(inode)
    return out


class ProcessResolver:
    """Maps (protocol, local address, port) to a Process, caching inode and process data."""

    def __init__(self, proc_root: str = "/proc", containers=None) -> None:
        self.root = proc_root
        self.inode_pid: dict[int, int] = {}
        self.scanned_pids: set[int] = set()
        self.cache: dict[tuple[int, str], Process] = {}
        self.containers = containers  # ContainerMap or None
        self._last_full = 0.0

    def resolve(self, proto: str, port: int, ip: str = "", netns_pid: int | None = None) -> Process | None:
        net_root = f"{self.root}/{netns_pid}" if netns_pid else self.root
        inodes = socket_inodes(proto, port, net_root, ip)
        for inode in inodes:
            pid = self._pid_for_inode(inode)
            if pid:
                return self.process(pid)
        return None

    def _pid_for_inode(self, inode: int) -> int | None:
        if inode in self.inode_pid and os.path.exists(f"{self.root}/{self.inode_pid[inode]}"):
            return self.inode_pid[inode]
        pids = self._pids()
        new = [p for p in pids if p not in self.scanned_pids]
        self._index(new)  # new processes first: they made most new sockets
        if inode not in self.inode_pid and time.monotonic() - self._last_full > 1.0:
            self._last_full = time.monotonic()
            self.scanned_pids &= set(pids)
            self._index(pids)
        return self.inode_pid.get(inode)

    def _pids(self) -> list[int]:
        try:
            return sorted((int(d) for d in os.listdir(self.root) if d.isdigit()), reverse=True)
        except OSError:
            return []

    def _index(self, pids: list[int]) -> None:
        for pid in pids:
            self.scanned_pids.add(pid)
            fd_dir = f"{self.root}/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue
            for fd in fds:
                try:
                    target = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                if target.startswith("socket:["):
                    self.inode_pid[int(target[8:-1])] = pid

    def _starttime(self, pid: int) -> str:
        stat = _read(f"{self.root}/{pid}/stat").decode("ascii", "replace")
        fields = stat.rpartition(")")[2].split()
        return fields[19] if len(fields) > 19 else ""

    def process(self, pid: int, depth: int = 0) -> Process | None:
        key = (pid, self._starttime(pid))
        if key in self.cache:
            return self.cache[key]
        base = f"{self.root}/{pid}"
        stat = _read(f"{base}/stat").decode("utf-8", "replace")
        if not stat:
            return None
        name = stat[stat.find("(") + 1:stat.rfind(")")]
        fields = stat.rpartition(")")[2].split()
        ppid = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else 0
        try:
            exe = os.readlink(f"{base}/exe")
        except OSError:
            exe = ""
        argv = [a.decode("utf-8", "replace") for a in _read(f"{base}/cmdline").split(b"\0") if a]
        try:
            cwd = os.readlink(f"{base}/cwd")
        except OSError:
            cwd = ""
        cid = container_id(_read(f"{base}/cgroup").decode("ascii", "replace"))
        proc = Process(pid=pid, name=name, exe=exe, cmdline=" ".join(argv)[:2000], ppid=ppid)
        proc.category = classify(name, exe, argv, cid)
        if cid:
            proc.container = cid[:12]
            if self.containers is not None:
                info = self.containers.by_id(cid)
                if info:
                    proc.container, proc.image = info.name, info.image
        if proc.category in ("interpreter", "package_manager"):
            proc.env = env_for(exe, cwd, _environ_vars(f"{base}/environ"), proc.category, argv[0] if argv else "")
        if ppid > 1 and depth < 5:
            parent = self.process(ppid, depth + 1)
            if parent is not None:
                proc.parent = parent.exe or parent.name
                # A plain tool (curl, sh, git) run by pip/npm/python counts as its ancestor (install hooks).
                if proc.category == "other" and parent.category in ("package_manager", "interpreter"):
                    proc.category, proc.via = parent.category, parent.via or (parent.exe or parent.name)
                    proc.env = proc.env or parent.env
        self.cache[key] = proc
        if len(self.cache) > 4096:
            self.cache.pop(next(iter(self.cache)))
        return proc


def _environ_vars(path: str) -> dict[str, str]:
    """Only VIRTUAL_ENV and CONDA_PREFIX are read from a process environment; nothing is stored."""
    out = {}
    for item in _read(path, 1 << 20).split(b"\0"):
        for var in (b"VIRTUAL_ENV=", b"CONDA_PREFIX="):
            if item.startswith(var):
                out[var[:-1].decode()] = item[len(var):].decode("utf-8", "replace")
    return out


@dataclass
class ContainerInfo:
    id: str
    name: str
    image: str
    ips: list[str] = field(default_factory=list)
    pid: int = 0


class ContainerMap:
    """Running Docker containers by id and IP, refreshed from `docker inspect` (MON-2)."""

    def __init__(self, docker: str = "docker", ttl: float = 30.0) -> None:
        self.docker = docker
        self.ttl = ttl
        self.items: dict[str, ContainerInfo] = {}
        self._at = 0.0

    def refresh(self, force: bool = False) -> None:
        if not force and time.monotonic() - self._at < self.ttl:
            return
        self._at = time.monotonic()
        import json
        import shutil
        import subprocess

        if not shutil.which(self.docker):
            return
        try:
            ids = subprocess.run([self.docker, "ps", "-q", "--no-trunc"], capture_output=True, text=True,
                                 timeout=10, check=False).stdout.split()
            if not ids:
                self.items = {}
                return
            data = json.loads(subprocess.run([self.docker, "inspect", *ids], capture_output=True, text=True,
                                             timeout=20, check=False).stdout or "[]")
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return
        items = {}
        for c in data:
            nets = (c.get("NetworkSettings") or {}).get("Networks") or {}
            ips = [n.get("IPAddress") for n in nets.values() if n.get("IPAddress")]
            ips += [n.get("GlobalIPv6Address") for n in nets.values() if n.get("GlobalIPv6Address")]
            items[c["Id"]] = ContainerInfo(c["Id"], c.get("Name", "").lstrip("/"),
                                           (c.get("Config") or {}).get("Image", ""), ips,
                                           (c.get("State") or {}).get("Pid", 0))
        self.items = items

    def by_id(self, cid: str) -> ContainerInfo | None:
        self.refresh()
        return self.items.get(cid)

    def by_ip(self, ip: str) -> ContainerInfo | None:
        self.refresh()
        return next((c for c in self.items.values() if ip in c.ips), None)
