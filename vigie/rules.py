"""Les règles de détection : des fichiers YAML lisibles, inspirés de Sigma.

Trois types de règles :
  - simple      : un seul événement suffit (ex. journal effacé) ;
  - threshold   : N événements, ou N valeurs différentes, dans une fenêtre de temps (ex. force brute) ;
  - sequence    : une étape puis une autre, pour la même clé (ex. échecs puis connexion réussie).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .events import Event

SEVERITIES = ("low", "medium", "high", "critical")
DURATION = re.compile(r"^(\d+)\s*(s|m|h|d)$")


class RuleError(ValueError):
    pass


def parse_duration(text: str | int) -> timedelta:
    if isinstance(text, int):
        return timedelta(seconds=text)
    m = DURATION.match(str(text).strip())
    if not m:
        raise RuleError(f"durée invalide : {text!r} (exemples : 30s, 5m, 1h)")
    unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m[2]]
    return timedelta(**{unit: int(m[1])})


def _norm(v: Any) -> Any:
    return v.lower() if isinstance(v, str) else v


def match_value(value: Any, cond: Any) -> bool:
    """Compare un champ à une condition. Les chaînes sont comparées sans tenir compte de la casse."""
    if isinstance(cond, dict):
        ok = True
        for op, arg in cond.items():
            if op == "contains":
                args = arg if isinstance(arg, list) else [arg]
                ok &= isinstance(value, str) and any(str(a).lower() in value.lower() for a in args)
            elif op == "startswith":
                args = arg if isinstance(arg, list) else [arg]
                ok &= isinstance(value, str) and any(value.lower().startswith(str(a).lower()) for a in args)
            elif op == "regex":
                ok &= isinstance(value, str) and re.search(arg, value, re.I) is not None
            elif op == "not":
                ok &= not match_value(value, arg)
            elif op == "gte":
                ok &= isinstance(value, (int, float)) and value >= arg
            elif op == "exists":
                ok &= (value not in (None, "")) == bool(arg)
            else:
                raise RuleError(f"opérateur inconnu : {op}")
        return ok
    if isinstance(cond, list):
        return any(match_value(value, c) for c in cond)
    return _norm(value) == _norm(cond)


def match_event(ev: Event, spec: dict[str, Any]) -> bool:
    return all(match_value(ev.get(k), c) for k, c in spec.items())


@dataclass
class Rule:
    id: str
    title: str
    description: str
    severity: str
    mitre: list[str]
    match: dict[str, Any]
    message: str = ""
    threshold: dict[str, Any] | None = None
    sequence: dict[str, Any] | None = None
    dedup: dict[str, Any] | None = None
    references: list[str] = field(default_factory=list)
    file: str = ""

    @property
    def kind(self) -> str:
        return "sequence" if self.sequence else "threshold" if self.threshold else "simple"

    def matches(self, ev: Event) -> bool:
        return match_event(ev, self.match)


def _check(d: dict, path: str) -> Rule:
    for k in ("id", "title", "severity"):
        if k not in d:
            raise RuleError(f"{path} : champ obligatoire manquant « {k} »")
    if d["severity"] not in SEVERITIES:
        raise RuleError(f"{path} : sévérité inconnue {d['severity']!r} ({', '.join(SEVERITIES)})")
    if "match" not in d and "sequence" not in d:
        raise RuleError(f"{path} : il faut un bloc « match » ou « sequence »")
    th, seq, dd = d.get("threshold"), d.get("sequence"), d.get("dedup")
    if th:
        th = {**th, "window": parse_duration(th.get("window", "5m"))}
        if "count" not in th or "group_by" not in th:
            raise RuleError(f"{path} : un seuil demande « count » et « group_by »")
    if seq:
        seq = {**seq, "window": parse_duration(seq.get("window", "15m"))}
        if len(seq.get("steps", [])) < 2 or "key" not in seq:
            raise RuleError(f"{path} : une séquence demande « key » et au moins deux « steps »")
    if dd:
        dd = {**dd, "window": parse_duration(dd.get("window", "10m"))}
    return Rule(id=str(d["id"]), title=d["title"], description=d.get("description", "").strip(), severity=d["severity"],
                mitre=[str(x) for x in d.get("mitre", [])], match=d.get("match", {}), message=d.get("message", ""),
                threshold=th, sequence=seq, dedup=dd, references=d.get("references", []), file=path)


def load_rules(folder: str | Path) -> list[Rule]:
    folder = Path(folder)
    rules = []
    for f in sorted(folder.glob("*.y*ml")):
        data = yaml.safe_load(f.read_text(encoding="utf-8"))  # safe_load : jamais d'objet Python arbitraire
        rules.append(_check(data, f.name))
    ids = [r.id for r in rules]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise RuleError(f"identifiants en double : {', '.join(sorted(dup))}")
    return rules
