"""Le scénario de démonstration : une journée normale avec deux attaques cachées dedans.

Vigie doit trouver toutes les étapes des deux attaques, et rien d'autre dans le bruit de fond.
"""
import json
from pathlib import Path

from vigie.cli import DEFAULT_RULES, main
from vigie.engine import analyse, incidents
from vigie.parsers import parse_paths
from vigie.report import to_html, to_json
from vigie.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = json.loads((ROOT / "tests" / "expected.json").read_text())


def scan():
    events, stats = parse_paths([ROOT / "samples"], year=2026, tz="Europe/Paris")
    return events, stats, analyse(events, load_rules(DEFAULT_RULES))


def primary_key(alert):
    if alert.key:
        return next(iter(alert.key.values()))
    e = alert.events[0]
    return e.user or e.host


def test_every_attack_step_is_detected_and_nothing_else():
    _, _, alerts = scan()
    found = sorted((a.rule.id, primary_key(a)) for a in alerts)
    expected = sorted((x["rule"], x["key"]) for x in EXPECTED)
    missing = set(expected) - set(found)
    extra = set(found) - set(expected)
    assert not missing, f"attaques manquées : {missing}"
    assert not extra, f"fausses alertes : {extra}"


def test_two_incidents_are_reconstructed():
    _, _, alerts = scan()
    inc = incidents(alerts)
    assert len(inc) == 2
    assert {ip for g in inc for ip in g["ips"]} == {"203.0.113.45", "198.51.100.23"}
    assert all(g["severity"] == "critical" for g in inc)


def test_reports_escape_log_content(tmp_path):
    # un journal peut contenir du HTML piégé : le rapport doit l'afficher, jamais l'exécuter
    line = '6.6.6.6 - - [28/Oct/2026:22:00:00 +0100] "GET /?q=<script>alert(1)</script> HTTP/1.1" 200 10 "-" "<img src=x onerror=alert(2)>"'
    log = tmp_path / "piege.log"
    log.write_text(line + "\n", encoding="utf-8")
    events, stats = parse_paths([log], year=2026)
    alerts = analyse(events, load_rules(DEFAULT_RULES))
    page = to_html(alerts, events, stats)
    assert alerts, "la tentative de XSS doit être détectée"
    assert "<script>alert(1)</script>" not in page and "<img src=x" not in page
    assert "&lt;script&gt;" in page


def test_json_report():
    events, stats, alerts = scan()
    data = json.loads(to_json(alerts, events, stats))
    assert len(data["alerts"]) == len(EXPECTED) and len(data["incidents"]) == 2


def test_cli_exit_codes(tmp_path, capsys):
    out = tmp_path / "r.html"
    assert main(["scan", str(ROOT / "samples"), "--year", "2026", "-f", "html", "-o", str(out)]) == 0
    assert out.read_text().startswith("<!doctype html>")
    assert main(["scan", str(ROOT / "samples"), "--year", "2026", "--fail-on", "critical"]) == 2
    assert main(["rules"]) == 0
    assert "15 règles" in capsys.readouterr().out
