"""Journaux d'authentification Linux (auth.log / secure) : sshd, sudo, useradd, usermod.

Accepte l'horodatage syslog classique (« Oct 28 21:14:03 », sans année)
et l'horodatage ISO 8601 de rsyslog (« 2026-10-28T21:14:03+01:00 »).
"""
from __future__ import annotations

import re
from datetime import datetime

from ..events import Event

SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?)\s+(?P<host>\S+)\s+(?P<prog>[\w./-]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")

SSH_FAIL = re.compile(r"Failed (?:password|publickey) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)")
SSH_OK = re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)")
SUDO = re.compile(r"^\s*(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.+)$")
USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
GROUPADD = re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")


def parse_ts(text: str, year: int) -> datetime:
    if text[:4].isdigit():
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    return datetime.strptime(f"{year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int, origin: str = "") -> Event | None:
    m = SYSLOG.match(line)
    if not m:
        return None
    prog, msg, host = m["prog"], m["msg"], m["host"]
    ts = parse_ts(m["ts"], year)
    base = dict(ts=ts, source="linux", host=host, raw=line, origin=origin)
    if prog == "sshd":
        if f := SSH_FAIL.search(msg):
            return Event(action="auth_failure", user=f["user"], src_ip=f["ip"],
                         fields={"service": "ssh", "invalid_user": bool(f["invalid"])}, **base)
        if s := SSH_OK.search(msg):
            return Event(action="auth_success", user=s["user"], src_ip=s["ip"],
                         fields={"service": "ssh", "method": s["method"]}, **base)
        return None
    if prog == "sudo" and (s := SUDO.match(msg)):
        return Event(action="sudo", user=s["user"], fields={"target_user": s["target"], "command": s["cmd"].strip()}, **base)
    if prog == "useradd" and (u := USERADD.search(msg)):
        return Event(action="account_created", user=u["user"], **base)
    if prog in ("usermod", "gpasswd") and (g := GROUPADD.search(msg)):
        return Event(action="group_member_added", user=g["user"], fields={"group": g["group"]}, **base)
    return None
