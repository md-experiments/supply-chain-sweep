"""Background service definitions (MON-NFR-8, MON-NFR-9).

Privileges the monitor needs, and why:

- CAP_NET_RAW: open the AF_PACKET socket that observes DNS packets and TCP SYNs.
- CAP_SYS_PTRACE: read other users' /proc/<pid>/fd to map a socket to its process.
- CAP_DAC_READ_SEARCH: read /proc/<pid>/{exe,cwd,environ} of other users' processes, and
  their scanner inventories (for linking findings to environments).
- CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN (eBPF attribution only): load the bpftrace
  tracepoint programs and use tracefs. Set `attribution = "proc"` in the config and
  remove these three to run without eBPF.
- CAP_SYS_RESOURCE (eBPF only): raise RLIMIT_MEMLOCK for BPF maps on older kernels.

Nothing else is requested: the unit drops every other capability, forbids
privilege escalation and makes the filesystem read-only except the data dir.
The data dir is readable by the notify user's group only (UMask 0027), so other
local users cannot read the DNS history.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

SYSTEMD_PATH = Path("/etc/systemd/system/sweep-monitor.service")
LAUNCHD_PATH = Path("/Library/LaunchDaemons/com.supply-chain-sweep.monitor.plist")
DATA_DIR = "/var/lib/supply-chain-sweep"


def _exe() -> list[str]:
    exe = shutil.which("sweep")
    return [exe] if exe else [sys.executable, "-m", "supply_chain_sweep"]


CAPS = "CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE"


def systemd_unit(notify_user: str = "") -> str:
    cmd = " ".join([*_exe(), "monitor", "run"])
    env = f"Environment=SWEEP_HOME={DATA_DIR}\n"
    if notify_user:
        import grp
        import pwd

        try:
            group = grp.getgrgid(pwd.getpwnam(notify_user).pw_gid).gr_name
        except KeyError:
            group = ""
        env += f"Environment=SUDO_USER={notify_user}\n"
        if group:
            env += f"Group={group}\n"
    return f"""[Unit]
Description=supply-chain-sweep network monitor (DNS and connection attribution)
Documentation=https://github.com/md-experiments/supply-chain-sweep
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={cmd}
Restart=always
RestartSec=5
{env}StateDirectory=supply-chain-sweep
StateDirectoryMode=0750
UMask=0027
# Least privilege: only what capture and attribution need (see `sweep monitor install --help`).
CapabilityBoundingSet={CAPS}
AmbientCapabilities={CAPS}
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={DATA_DIR}
PrivateTmp=yes
Nice=10
CPUQuota=5%
# bpftrace maps ~60 MB of shared LLVM code; its private memory is ~30 MB.
MemoryMax=300M

[Install]
WantedBy=multi-user.target
"""


def launchd_plist() -> str:
    args = "".join(f"<string>{a}</string>" for a in [*_exe(), "monitor", "run"])
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.supply-chain-sweep.monitor</string>
  <key>ProgramArguments</key><array>{args}</array>
  <key>EnvironmentVariables</key><dict><key>SWEEP_HOME</key><string>{DATA_DIR}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>/var/log/sweep-monitor.log</string>
</dict></plist>
"""


def service_definition(notify_user: str = "") -> tuple[Path, str, list[list[str]]]:
    """(path, contents, commands to enable it) for this platform."""
    if sys.platform == "darwin":
        return LAUNCHD_PATH, launchd_plist(), [["launchctl", "load", "-w", str(LAUNCHD_PATH)]]
    return SYSTEMD_PATH, systemd_unit(notify_user), [["systemctl", "daemon-reload"],
                                                     ["systemctl", "enable", "--now", "sweep-monitor"]]
