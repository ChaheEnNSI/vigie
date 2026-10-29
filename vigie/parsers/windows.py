"""Journal de sécurité Windows, exporté en JSON avec PowerShell (voir le README).

Chaque objet : {"TimeCreated": "...", "Id": 4625, "MachineName": "DC01", "EventData": {...}}
Le fichier peut être un tableau JSON ou un objet JSON par ligne.
"""
from __future__ import annotations

import json
import re
from datetime import datetime

from ..events import Event

CN = re.compile(r"CN=([^,]+)", re.I)
EMPTY = {"", "-", "::1", "127.0.0.1", None}


def _ts(text: str) -> datetime:
    text = text.strip()
    m = re.match(r"/Date\((\d+)\)/", text)  # ancien format de ConvertTo-Json
    if m:
        from datetime import timezone
        return datetime.fromtimestamp(int(m[1]) / 1000, tz=timezone.utc)
    if "." in text:  # 7 décimales côté .NET : on garde les microsecondes
        head, _, tail = text.partition(".")
        frac = re.match(r"\d+", tail)[0]
        text = f"{head}.{frac[:6].ljust(6, '0')}{tail[len(frac):]}"
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def to_event(rec: dict, origin: str = "") -> Event | None:
    if not isinstance(rec, dict) or "TimeCreated" not in rec:
        return None  # pas un événement Windows : ignoré (et compté)
    eid = int(rec.get("Id", rec.get("EventID", 0)))
    d = rec.get("EventData") or {}
    host = rec.get("MachineName", "")
    base = dict(ts=_ts(rec["TimeCreated"]), source="windows", host=host, raw=json.dumps(rec, ensure_ascii=False), origin=origin)
    ip = d.get("IpAddress", "")
    ip = "" if ip in EMPTY else ip
    f = {"event_id": eid}
    if eid == 4625:
        return Event(action="auth_failure", user=d.get("TargetUserName", ""), src_ip=ip,
                     fields={**f, "logon_type": str(d.get("LogonType", "")), "status": d.get("Status", "")}, **base)
    if eid == 4624:
        return Event(action="auth_success", user=d.get("TargetUserName", ""), src_ip=ip,
                     fields={**f, "logon_type": str(d.get("LogonType", ""))}, **base)
    if eid == 4720:
        return Event(action="account_created", user=d.get("TargetUserName", ""), fields={**f, "by": d.get("SubjectUserName", "")}, **base)
    if eid in (4728, 4732, 4756):
        member = d.get("MemberName", "") or d.get("MemberSid", "")
        cn = CN.search(member)
        return Event(action="group_member_added", user=cn[1] if cn else member,
                     fields={**f, "group": d.get("TargetUserName", ""), "by": d.get("SubjectUserName", "")}, **base)
    if eid == 1102:
        return Event(action="log_cleared", user=d.get("SubjectUserName", ""), fields=f, **base)
    if eid == 7045:
        return Event(action="service_installed", fields={**f, "service": d.get("ServiceName", ""), "image_path": d.get("ImagePath", "")}, **base)
    if eid == 4688:
        return Event(action="process_created", user=d.get("SubjectUserName", ""),
                     fields={**f, "process": d.get("NewProcessName", ""), "command_line": d.get("CommandLine", "")}, **base)
    return None


def parse_text(text: str, origin: str = "") -> tuple[list[Event], int]:
    """Renvoie (événements reconnus, enregistrements ignorés)."""
    text = text.strip().lstrip("\ufeff")
    if not text:
        return [], 0
    records = json.loads(text) if text.startswith("[") else [json.loads(x) for x in text.splitlines() if x.strip()]
    if isinstance(records, dict):
        records = [records]
    out, skipped = [], 0
    for i, rec in enumerate(records, 1):
        ev = to_event(rec, f"{origin}#{i}")
        if ev:
            out.append(ev)
        else:
            skipped += 1
    return out, skipped
