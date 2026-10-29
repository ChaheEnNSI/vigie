"""Lecture des fichiers : on reconnaît le format tout seul, ligne par ligne."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from ..events import Event
from . import firewall, linux_auth, web_access, windows

LINE_PARSERS = (linux_auth.parse_line, firewall.parse_line, web_access.parse_line)


def parse_file(path: str | Path, year: int | None = None) -> tuple[list[Event], int]:
    """Renvoie (événements reconnus, lignes ignorées)."""
    path = Path(path)
    year = year or datetime.now().year
    text = path.read_text(encoding="utf-8", errors="replace")
    head = text.lstrip("﻿ \n\r\t")[:1]
    if head in "[{":
        try:
            return windows.parse_text(text, path.name)
        except ValueError:  # JSON invalide : on n'arrête pas toute l'analyse pour un fichier
            return [], 1
    events, skipped = [], 0
    for n, line in enumerate(text.splitlines(), 1):
        line = line.rstrip()
        if not line:
            continue
        origin = f"{path.name}:{n}"
        for parse in LINE_PARSERS:
            ev = parse(line, year, origin)
            if ev:
                events.append(ev)
                break
        else:
            skipped += 1
    return events, skipped


def parse_paths(paths: list[str | Path], year: int | None = None, tz: str | None = None) -> tuple[list[Event], dict]:
    """Lit des fichiers ou des dossiers ; renvoie les événements triés et des statistiques.

    Toutes les heures sont ramenées dans un même fuseau (tz, sinon celui de la machine), puis
    rendues « naïves » : syslog n'a pas de fuseau, et les règles comparent des sources différentes.
    """
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(x for x in p.iterdir() if x.is_file() and x.suffix in (".log", ".json", ".txt", ""))
        elif p.is_file():
            files.append(p)
    events, stats = [], {"files": [], "skipped": 0}
    for f in files:
        evs, skipped = parse_file(f, year)
        events += evs
        stats["files"].append({"name": f.name, "events": len(evs), "skipped": skipped})
        stats["skipped"] += skipped
    zone = ZoneInfo(tz) if tz else None
    for e in events:
        if e.ts.tzinfo is not None:
            e.ts = e.ts.astimezone(zone).replace(tzinfo=None)
    events.sort(key=lambda e: e.ts)
    return events, stats
