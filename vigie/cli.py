"""Ligne de commande.

  python -m vigie scan samples/                       # tableau dans le terminal
  python -m vigie scan /var/log/auth.log -f html -o rapport.html
  python -m vigie rules                                # liste des règles
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, mitre
from .engine import analyse
from .parsers import parse_paths
from .report import table, to_html, to_json
from .rules import SEVERITIES, RuleError, load_rules

# les règles livrées avec Vigie ; -r permet d'utiliser les vôtres
DEFAULT_RULES = Path(__file__).resolve().parent / "detections"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vigie", description="Vigie : détecte les attaques dans vos journaux (Linux, Windows, web, pare-feu).")
    p.add_argument("--version", action="version", version=f"vigie {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="analyser des fichiers ou des dossiers de journaux")
    s.add_argument("paths", nargs="+", help="fichiers ou dossiers")
    s.add_argument("-r", "--rules", default=str(DEFAULT_RULES), help="dossier des règles YAML")
    s.add_argument("-f", "--format", choices=("table", "json", "html"), default="table")
    s.add_argument("-o", "--output", help="fichier de sortie (sinon : écran)")
    s.add_argument("--min-severity", choices=SEVERITIES, default="low", help="gravité minimale affichée")
    s.add_argument("--year", type=int, help="année des journaux syslog (ils ne l'indiquent pas)")
    s.add_argument("--tz", help="fuseau horaire d'affichage, ex. Europe/Paris (défaut : celui de la machine)")
    s.add_argument("--fail-on", choices=SEVERITIES, help="code de sortie 2 si une alerte atteint cette gravité (utile en CI)")
    s.add_argument("--no-color", action="store_true")

    r = sub.add_parser("rules", help="lister les règles de détection")
    r.add_argument("-r", "--rules", default=str(DEFAULT_RULES))

    a = p.parse_args(argv)
    try:
        rules = load_rules(a.rules)
    except RuleError as exc:
        print(f"Erreur dans les règles : {exc}", file=sys.stderr)
        return 3
    if not rules:
        print(f"Aucune règle trouvée dans {a.rules} (indiquez le dossier avec -r).", file=sys.stderr)
        return 3

    if a.cmd == "rules":
        for rule in rules:
            tech = ", ".join(f"{t} ({mitre.name(t)})" for t in rule.mitre)
            print(f"{rule.id}  {rule.severity:<8}  {rule.kind:<9}  {rule.title}\n           {tech}")
        print(f"\n{len(rules)} règles")
        return 0

    events, stats = parse_paths(a.paths, a.year, a.tz)
    if not events:
        print("Aucun événement reconnu dans ces fichiers.", file=sys.stderr)
        return 1
    alerts = analyse(events, rules, a.min_severity)
    if a.format == "table":
        out = table(alerts, color=not a.no_color and not a.output and sys.stdout.isatty())
        out = f"{len(events)} événements lus ({stats['skipped']} lignes ignorées)\n\n" + out
    elif a.format == "json":
        out = to_json(alerts, events, stats)
    else:
        out = to_html(alerts, events, stats)
    if a.output:
        Path(a.output).write_text(out, encoding="utf-8")
        print(f"{len(alerts)} alertes · rapport écrit dans {a.output}")
    else:
        print(out)
    if a.fail_on and any(SEVERITIES.index(x.severity) >= SEVERITIES.index(a.fail_on) for x in alerts):
        return 2
    return 0
