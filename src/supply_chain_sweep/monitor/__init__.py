"""Network monitor: DNS lookups and outbound connections, attributed to processes.

The scanner finds malicious packages at rest; the monitor catches them when they
call home. It observes traffic (never proxies or blocks it), keeps everything in a
local SQLite database, and reports through the scanner's finding and report types.
"""
