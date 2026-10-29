"""Journaux d'accès web au format « combined » (Apache, Nginx).

Exemple : 203.0.113.45 - - [28/Oct/2026:21:02:11 +0100] "GET /produits.php?id=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"
L'URL est décodée (%27 → ') pour que les règles voient ce que l'attaquant a vraiment envoyé.
"""
from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import unquote_plus

from ..events import Event

COMBINED = re.compile(
    r'^(?P<ip>[\da-fA-F.:]+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)(?: (?P<proto>[^"]+))?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_line(line: str, year: int = 0, origin: str = "") -> Event | None:
    m = COMBINED.match(line)
    if not m:
        return None
    ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    url = m["url"]
    decoded = unquote_plus(unquote_plus(url))  # double décodage : contournements fréquents (%2527)
    return Event(ts=ts, source="web", action="http_request", src_ip=m["ip"],
                 user="" if m["user"] == "-" else m["user"],
                 fields={"method": m["method"], "url": decoded, "path": decoded.split("?", 1)[0],
                         "status": int(m["status"]), "user_agent": m["ua"] or "", "referer": m["ref"] or ""},
                 raw=line, origin=origin)
