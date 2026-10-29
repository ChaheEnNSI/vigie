"""Journaux de pare-feu Linux (iptables / UFW) écrits par le noyau dans syslog.

Exemple : « Oct 28 20:58:01 fw01 kernel: [UFW BLOCK] IN=eth0 … SRC=203.0.113.45 DST=192.0.2.10 … PROTO=TCP SPT=40000 DPT=22 »
"""
from __future__ import annotations

import re

from ..events import Event
from .linux_auth import SYSLOG, parse_ts

KV = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT|IN|OUT)=(\S*)")
VERDICT = re.compile(r"\[(?:UFW )?(BLOCK|ALLOW|AUDIT|DROP|REJECT|ACCEPT)\]", re.I)


def parse_line(line: str, year: int, origin: str = "") -> Event | None:
    m = SYSLOG.match(line)
    if not m or m["prog"] != "kernel" or "SRC=" not in m["msg"]:
        return None
    kv = dict(KV.findall(m["msg"]))
    v = VERDICT.search(m["msg"])
    verdict = (v[1].upper() if v else "BLOCK")
    action = "conn_allowed" if verdict in ("ALLOW", "ACCEPT", "AUDIT") else "conn_blocked"
    port = kv.get("DPT")
    return Event(ts=parse_ts(m["ts"], year), source="firewall", action=action, host=m["host"],
                 src_ip=kv.get("SRC", ""), dst_ip=kv.get("DST", ""), dst_port=int(port) if port and port.isdigit() else None,
                 fields={"proto": kv.get("PROTO", ""), "verdict": verdict}, raw=line, origin=origin)
