"""Le moteur : il passe les événements dans l'ordre du temps et lève des alertes."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .events import Event
from .rules import SEVERITIES, Rule, match_event

MAX_EVIDENCE = 25


@dataclass
class Alert:
    rule: Rule
    key: dict[str, str]
    first: datetime
    last: datetime
    events: list[Event] = field(default_factory=list)
    count: int = 0
    distinct: set = field(default_factory=set)

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def when(self) -> datetime:
        """L'instant qui compte : pour une séquence, le moment où elle aboutit."""
        return self.last if self.rule.kind == "sequence" else self.first

    @property
    def score(self) -> int:
        return SEVERITIES.index(self.rule.severity)

    def add(self, ev: Event, value=None) -> None:
        self.count += 1
        self.last = max(self.last, ev.ts)
        if value not in (None, ""):
            self.distinct.add(value)
        if len(self.events) < MAX_EVIDENCE:
            self.events.append(ev)

    @property
    def message(self) -> str:
        e0 = self.events[0] if self.events else None
        ctx = {"count": self.count, "distinct": len(self.distinct), "duration": human(self.last - self.first),
               **{k: v for k, v in self.key.items()}}
        if e0:
            for k in ("user", "src_ip", "host", "dst_ip"):
                ctx.setdefault(k, e0.get(k) or "?")
            for k, v in e0.fields.items():
                ctx.setdefault(k, v)
        try:
            return (self.rule.message or self.rule.title).format(**ctx)
        except (KeyError, IndexError, ValueError):
            return self.rule.title

    def to_dict(self) -> dict:
        return {"rule": self.rule.id, "title": self.rule.title, "severity": self.severity, "mitre": self.rule.mitre,
                "key": self.key, "when": self.when.isoformat(), "first": self.first.isoformat(), "last": self.last.isoformat(), "count": self.count,
                "message": self.message, "evidence": [e.origin for e in self.events]}


def human(d: timedelta) -> str:
    s = int(d.total_seconds())
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s" if s % 60 else f"{s // 60} min"
    return f"{s // 3600} h {(s % 3600) // 60:02d}"


def _key(ev: Event, fields: list[str] | str) -> tuple:
    fields = [fields] if isinstance(fields, str) else fields
    return tuple(str(ev.get(f) or "") for f in fields)


def _keydict(fields: list[str] | str, values: tuple) -> dict[str, str]:
    fields = [fields] if isinstance(fields, str) else fields
    return dict(zip(fields, values, strict=True))


def run_rule(rule: Rule, events: list[Event]) -> list[Alert]:
    if rule.kind == "simple":
        return _simple(rule, events)
    if rule.kind == "threshold":
        return _threshold(rule, events)
    return _sequence(rule, events)


def _simple(rule: Rule, events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    open_: dict[tuple, Alert] = {}
    dd = rule.dedup
    for ev in events:
        if not rule.matches(ev):
            continue
        if dd:  # regroupe les répétitions (un scanner qui envoie 300 requêtes = une alerte)
            k = _key(ev, dd["key"])
            a = open_.get(k)
            if a and ev.ts - a.last <= dd["window"]:
                a.add(ev)
                continue
            a = Alert(rule, _keydict(dd["key"], k), ev.ts, ev.ts)
            a.add(ev)
            open_[k] = a
            alerts.append(a)
        else:
            a = Alert(rule, {k: str(ev.get(k)) for k in ("user", "host") if ev.get(k)}, ev.ts, ev.ts)
            a.add(ev)
            alerts.append(a)
    return alerts


def _threshold(rule: Rule, events: list[Event]) -> list[Alert]:
    th = rule.threshold
    win, need, field_ = th["window"], int(th["count"]), th.get("distinct")
    buckets: dict[tuple, deque] = defaultdict(deque)
    current: dict[tuple, Alert] = {}
    alerts: list[Alert] = []
    for ev in events:
        if not rule.matches(ev):
            continue
        k = _key(ev, th["group_by"])
        if not any(k):
            continue
        a = current.get(k)
        if a and ev.ts - a.last <= win:  # l'attaque continue : on enrichit la même alerte
            a.add(ev, ev.get(field_) if field_ else None)
            continue
        q = buckets[k]
        q.append(ev)
        while q and ev.ts - q[0].ts > win:
            q.popleft()
        reached = len({e.get(field_) for e in q if e.get(field_) not in (None, "")}) if field_ else len(q)
        if reached >= need:
            a = Alert(rule, _keydict(th["group_by"], k), q[0].ts, q[0].ts)
            for e in q:
                a.add(e, e.get(field_) if field_ else None)
            alerts.append(a)
            current[k] = a
            q.clear()
    return alerts


def _sequence(rule: Rule, events: list[Event]) -> list[Alert]:
    seq = rule.sequence
    steps, win = seq["steps"], seq["window"]
    state: dict[tuple, dict] = {}
    alerts: list[Alert] = []
    for ev in events:
        if rule.match and not rule.matches(ev):
            continue
        k = _key(ev, seq["key"])
        if not any(k):
            continue
        st = state.setdefault(k, {"i": 0, "hits": [], "start": None})
        if st["start"] and ev.ts - st["start"] > win:  # trop tard : on repart de zéro
            st.update(i=0, hits=[], start=None)
        step = steps[st["i"]]
        if match_event(ev, step["match"]):
            st["hits"].append(ev)
            st["start"] = st["start"] or ev.ts
            n_step = sum(1 for e in st["hits"] if match_event(e, step["match"]))
            if n_step >= int(step.get("min", 1)):
                st["i"] += 1
                if st["i"] == len(steps):
                    a = Alert(rule, _keydict(seq["key"], k), st["start"], ev.ts)
                    for e in st["hits"]:
                        a.add(e)
                    alerts.append(a)
                    st.update(i=0, hits=[], start=None)
        elif st["i"] > 0 and match_event(ev, steps[st["i"] - 1]["match"]):
            st["hits"].append(ev)  # l'étape précédente se répète : on la garde comme preuve
    return alerts


def analyse(events: list[Event], rules: list[Rule], min_severity: str = "low") -> list[Alert]:
    floor = SEVERITIES.index(min_severity)
    alerts = [a for r in rules for a in run_rule(r, events) if a.score >= floor]
    alerts.sort(key=lambda a: (a.when, -a.score))
    return alerts


# actions qui « suivent » un compte : une connexion réussie, une élévation, une création…
LINK_ACTIONS = {"auth_success", "sudo", "account_created", "group_member_added", "process_created", "log_cleared"}


def _links(a: Alert) -> tuple[set, set, set]:
    ips = {e.src_ip for e in a.events if e.src_ip}
    users = {u for e in a.events if e.action in LINK_ACTIONS for u in (e.user, e.fields.get("by", "")) if u and u not in ("-", "?")}
    hosts = {e.host for e in a.events if e.host}
    return ips, users, hosts


def incidents(alerts: list[Alert], host_window: timedelta = timedelta(minutes=30)) -> list[dict]:
    """Regroupe les alertes en « incidents », comme le ferait un analyste :
    même adresse source, même compte compromis, ou à défaut même machine dans la demi-heure."""
    groups: list[dict] = []
    for a in sorted(alerts, key=lambda x: x.first):
        ips, users, hosts = _links(a)
        hits = [g for g in groups if (ips & g["ips"]) or (users & g["users"])]
        if not hits and not ips:
            hits = [g for g in groups if hosts & g["hosts"] and a.first - g["last"] <= host_window][-1:]
        if hits:  # une alerte peut relier deux incidents : on les fusionne
            g = hits[0]
            for other in hits[1:]:
                for k in ("ips", "users", "hosts"):
                    g[k] |= other[k]
                g["alerts"] += other["alerts"]
                g["last"] = max(g["last"], other["last"])
                groups.remove(other)
        else:
            g = {"ips": set(), "users": set(), "hosts": set(), "alerts": [], "last": a.last}
            groups.append(g)
        g["ips"] |= ips
        g["users"] |= users
        g["hosts"] |= hosts
        g["alerts"].append(a)
        g["last"] = max(g["last"], a.last)
    for g in groups:
        g["alerts"].sort(key=lambda x: x.when)
        g["first"] = min(a.first for a in g["alerts"])
        g["score"] = max(a.score for a in g["alerts"])
        g["severity"] = SEVERITIES[g["score"]]
        g["mitre"] = sorted({t for a in g["alerts"] for t in a.rule.mitre})
    groups.sort(key=lambda g: (-g["score"], g["first"]))
    return groups
