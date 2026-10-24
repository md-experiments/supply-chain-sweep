"""Kernel-side process attribution through bpftrace (optional; MON-5, MON-NFR-10).

/proc lookups race with fast resolvers: against a local caching resolver the
client's socket is often closed within a fraction of a millisecond, before user
space can look it up. Syscall tracepoints record the process at the moment it
sends, so nothing is missed:

- ``sys_enter_connect`` / ``sys_enter_sendto`` to port 53: pid, parent pid,
  command name and resolver address of every DNS client;
- ``sock:inet_sock_set_state`` (to SYN_SENT): the process opening each TCP
  connection, with its destination.

Only these fields are printed; packet contents never pass through eBPF. Needs
root (CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN for tracefs) and the `bpftrace` binary.
"""

from __future__ import annotations

import bisect
import os
import shutil
import subprocess
import threading
import time
from collections import defaultdict, deque

SCRIPT = r"""
tracepoint:syscalls:sys_enter_connect {
  $sa = (struct sockaddr_in *)uptr(args->uservaddr);
  if ($sa->sin_port == 0x3500) {
    if ($sa->sin_family == 2) {
      printf("U %llu %d %d %s %s\n", nsecs, pid, curtask->real_parent->tgid, ntop(2, $sa->sin_addr.s_addr), comm);
    }
    if ($sa->sin_family == 10) {
      $s6 = (struct sockaddr_in6 *)uptr(args->uservaddr);
      printf("U %llu %d %d %s %s\n", nsecs, pid, curtask->real_parent->tgid,
             ntop(10, $s6->sin6_addr.in6_u.u6_addr8), comm);
    }
  }
}
tracepoint:syscalls:sys_enter_sendto /args->addr != 0/ {
  $sa = (struct sockaddr_in *)uptr(args->addr);
  if ($sa->sin_port == 0x3500) {
    if ($sa->sin_family == 2) {
      printf("U %llu %d %d %s %s\n", nsecs, pid, curtask->real_parent->tgid, ntop(2, $sa->sin_addr.s_addr), comm);
    }
    if ($sa->sin_family == 10) {
      $s6 = (struct sockaddr_in6 *)uptr(args->addr);
      printf("U %llu %d %d %s %s\n", nsecs, pid, curtask->real_parent->tgid,
             ntop(10, $s6->sin6_addr.in6_u.u6_addr8), comm);
    }
  }
}
tracepoint:sock:inet_sock_set_state /args->newstate == 2 && args->protocol == 6/ {
  if (args->family == 2) {
    printf("T %llu %d %d %s:%d %s\n", nsecs, pid, curtask->real_parent->tgid, ntop(2, args->daddr), args->dport, comm);
  } else {
    printf("T %llu %d %d %s:%d %s\n", nsecs, pid, curtask->real_parent->tgid, ntop(10, args->daddr_v6), args->dport,
           comm);
  }
}
"""


class KernelAttributor:
    """Runs bpftrace and answers "which process sent to (proto, ip, port) around time t?"."""

    name = "ebpf-bpftrace"

    def __init__(self, bpftrace: str | None = None, keep: float = 10.0) -> None:
        self.bpftrace = bpftrace or shutil.which("bpftrace") or ""
        self.keep = keep
        self.proc: subprocess.Popen | None = None
        # (proto, ip, port) -> deque of (wall_ts, pid, ppid, comm), oldest first
        self.records: dict[tuple[str, str, int], deque] = defaultdict(deque)
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.error = ""
        self.lines = 0
        # bpftrace's nsecs is CLOCK_MONOTONIC; convert to wall-clock seconds.
        self._offset = time.time() - time.monotonic()

    @staticmethod
    def available() -> bool:
        return bool(shutil.which("bpftrace")) and hasattr(os, "geteuid") and os.geteuid() == 0

    def start(self, timeout: float = 20.0) -> bool:
        if not self.bpftrace:
            self.error = "bpftrace not installed"
            return False
        self.proc = subprocess.Popen([self.bpftrace, "-B", "none", "-e", SCRIPT], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, bufsize=1)
        threading.Thread(target=self._read, daemon=True).start()
        self.ready.wait(timeout)
        if not self.ready.is_set() or self.proc.poll() is not None:
            self.error = self.error or "bpftrace did not start"
            self.stop()
            return False
        return True

    def _read(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for line in self.proc.stdout:
            if line.startswith("Attaching"):
                self.ready.set()
                continue
            parts = line.split(None, 5)
            if len(parts) < 6 or parts[0] not in ("U", "T"):
                if line.startswith("ERROR") and "RLIMIT_MEMLOCK" not in line:
                    self.error = line.strip()
                continue
            kind, ns, pid, ppid, dest, comm = parts
            try:
                ts = int(ns) / 1e9 + self._offset
                if kind == "U":
                    key = ("udp", dest, 53)
                else:
                    ip, _, port = dest.rpartition(":")
                    key = ("tcp", ip, int(port))
                rec = (ts, int(pid), int(ppid), comm.strip())
            except ValueError:
                continue
            with self.lock:
                q = self.records[key]
                q.append(rec)
                while q and ts - q[0][0] > self.keep:
                    q.popleft()
            self.lines += 1
        self.ready.set()

    def lookup(self, proto: str, ip: str, port: int, ts: float, window: float = 1.0) -> tuple[int, int, str] | None:
        """The latest sender to (ip, port) at or shortly before `ts`."""
        with self.lock:
            q = self.records.get((proto, ip, port))
            if not q:
                return None
            times = [r[0] for r in q]
            i = bisect.bisect_right(times, ts + 0.05) - 1  # allow for clock skew between the two sources
            if i < 0 or ts - q[i][0] > window:
                return None
            _, pid, ppid, comm = q[i]
            return pid, ppid, comm

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
