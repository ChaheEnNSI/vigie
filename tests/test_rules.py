"""Le moteur de règles : conditions, seuils, séquences, et règles mal écrites."""
from datetime import datetime, timedelta

import pytest

from vigie.cli import DEFAULT_RULES
from vigie.engine import analyse, run_rule
from vigie.events import Event
from vigie.rules import RuleError, _check, load_rules, match_value, parse_duration

RULES = DEFAULT_RULES
T0 = datetime(2026, 10, 28, 21, 0, 0)


def ev(sec, action, **kw):
    fields = kw.pop("fields", {})
    return Event(ts=T0 + timedelta(seconds=sec), source=kw.pop("source", "linux"), action=action, fields=fields, **kw)


def test_conditions():
    assert match_value("Root", "root")  # sans tenir compte de la casse
    assert match_value("sudo", ["wheel", "sudo"])
    assert match_value("C:\\Users\\Public\\x.exe", {"contains": ["\\Users\\Public\\"]})
    assert match_value("/bin/bash", {"regex": r"(^|/)bash$"})
    assert not match_value("/usr/bin/apt update", {"regex": r"(^|/)bash$"})
    assert match_value(5, {"gte": 3})
    assert match_value("x", {"not": "y"})


def test_durations():
    assert parse_duration("90s") == timedelta(seconds=90)
    assert parse_duration("5m") == timedelta(minutes=5)
    with pytest.raises(RuleError):
        parse_duration("cinq minutes")


def test_all_shipped_rules_load():
    rules = load_rules(RULES)
    assert len(rules) == 15
    assert all(r.mitre for r in rules), "chaque règle doit citer au moins une technique MITRE ATT&CK"
    assert len({r.id for r in rules}) == len(rules)


def test_bad_rule_is_rejected():
    with pytest.raises(RuleError):
        _check({"id": "X", "title": "x", "severity": "énorme", "match": {}}, "x.yml")
    with pytest.raises(RuleError):
        _check({"id": "X", "title": "x", "severity": "high", "match": {}, "threshold": {"count": 3}}, "x.yml")


def rule(rid):
    return next(r for r in load_rules(RULES) if r.id == rid)


def test_threshold_fires_once_and_grows():
    events = [ev(i * 10, "auth_failure", src_ip="1.2.3.4", user="root") for i in range(20)]
    alerts = run_rule(rule("VIG-001"), events)
    assert len(alerts) == 1 and alerts[0].count == 20


def test_threshold_respects_window():
    # 8 échecs, mais étalés sur 35 minutes : pas une force brute
    events = [ev(i * 300, "auth_failure", src_ip="1.2.3.4", user="root") for i in range(8)]
    assert run_rule(rule("VIG-001"), events) == []


def test_distinct_threshold():
    events = [ev(i * 30, "auth_failure", src_ip="5.6.7.8", user=u) for i, u in enumerate(["a", "b", "c", "d", "e"])]
    assert len(run_rule(rule("VIG-002"), events)) == 1
    same = [ev(i * 30, "auth_failure", src_ip="5.6.7.8", user="a") for i in range(5)]
    assert run_rule(rule("VIG-002"), same) == []


def test_sequence_failures_then_success():
    events = [ev(i * 5, "auth_failure", src_ip="9.9.9.9", user="root") for i in range(6)] + [ev(60, "auth_success", src_ip="9.9.9.9", user="deploy")]
    alerts = run_rule(rule("VIG-003"), events)
    assert len(alerts) == 1 and alerts[0].when == T0 + timedelta(seconds=60)


def test_sequence_needs_enough_failures():
    # deux fautes de frappe puis la bonne connexion : rien d'anormal
    events = [ev(0, "auth_failure", src_ip="10.0.1.5", user="alice"), ev(5, "auth_failure", src_ip="10.0.1.5", user="alice"),
              ev(9, "auth_success", src_ip="10.0.1.5", user="alice")]
    assert run_rule(rule("VIG-003"), events) == []


def test_sequence_too_late():
    events = [ev(i * 5, "auth_failure", src_ip="9.9.9.9") for i in range(6)] + [ev(3600, "auth_success", src_ip="9.9.9.9")]
    assert run_rule(rule("VIG-003"), events) == []


def test_dedup_groups_a_scanner():
    events = [ev(i, "http_request", source="web", src_ip="7.7.7.7", fields={"url": f"/p?id=1 UNION SELECT {i}", "user_agent": "x"}) for i in range(50)]
    alerts = run_rule(rule("VIG-010"), events)
    assert len(alerts) == 1 and alerts[0].count == 50


def test_min_severity_filter():
    events = [ev(0, "account_created", user="x"), ev(1, "log_cleared", source="windows", user="y")]
    assert {a.rule.id for a in analyse(events, load_rules(RULES), "high")} == {"VIG-007"}
