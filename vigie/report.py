"""Les sorties : tableau dans le terminal, JSON pour d'autres outils, rapport HTML autonome."""
from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime

from . import __version__, mitre
from .engine import Alert, incidents
from .events import Event

SEV_FR = {"low": "faible", "medium": "moyenne", "high": "haute", "critical": "critique"}
SEV_COLOR = {"low": "\033[37m", "medium": "\033[33m", "high": "\033[31m", "critical": "\033[1;97;41m"}
RESET = "\033[0m"


# ---------------------------------------------------------------- terminal
def table(alerts: list[Alert], color: bool = True) -> str:
    if not alerts:
        return "Aucune alerte."
    rows = []
    for a in alerts:
        sev = SEV_FR[a.severity].upper()
        if color:
            sev = f"{SEV_COLOR[a.severity]}{sev:<8}{RESET}"
        else:
            sev = f"{sev:<8}"
        rows.append(f"{a.when:%d/%m %H:%M:%S}  {sev}  {a.rule.id}  {a.message}")
    by = Counter(a.severity for a in alerts)
    tail = " · ".join(f"{by[s]} {SEV_FR[s]}" for s in ("critical", "high", "medium", "low") if by[s])
    return "\n".join(rows) + f"\n\n{len(alerts)} alertes ({tail})"


# ---------------------------------------------------------------- JSON
def to_json(alerts: list[Alert], events: list[Event], stats: dict) -> str:
    inc = incidents(alerts)
    return json.dumps({
        "vigie": __version__,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "events": len(events),
        "files": stats.get("files", []),
        "alerts": [a.to_dict() for a in alerts],
        "incidents": [{"severity": g["severity"], "first": g["first"].isoformat(), "last": g["last"].isoformat(),
                       "ips": sorted(g["ips"]), "users": sorted(g["users"]), "mitre": g["mitre"],
                       "alerts": [a.rule.id for a in g["alerts"]]} for g in inc],
    }, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- HTML
CSS = """
:root{--bg:#0B0C1F;--panel:#14152E;--line:#26284A;--ink:#ECECF8;--ink2:#A9ABC9;--acc:#A9A7FF;--low:#8F93B8;--medium:#F2C14E;--high:#FF8A66;--critical:#FF4D6D}
*{box-sizing:border-box}html{background:var(--bg)}
body{margin:0;color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg)}
main{max-width:1180px;margin:0 auto;padding:40px 24px 80px}
h1{margin:0;font-size:clamp(28px,4vw,44px);letter-spacing:-.03em;line-height:1.05}
h2{margin:48px 0 14px;font-size:22px;letter-spacing:-.02em}
.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.k{margin:0 0 10px;font:500 12px/1 ui-monospace,Menlo,Consolas,monospace;letter-spacing:.12em;text-transform:uppercase;color:var(--acc)}
.sub{margin:10px 0 0;color:var(--ink2)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:28px}
.card{padding:16px 18px;border-radius:14px;background:var(--panel);border:1px solid var(--line)}
.card b{display:block;font-size:30px;letter-spacing:-.03em}
.card span{color:var(--ink2);font-size:13px}
.sev{display:inline-block;padding:2px 9px;border-radius:999px;font:600 11.5px/1.6 ui-monospace,Menlo,monospace;letter-spacing:.06em;text-transform:uppercase;color:#0B0C1F}
.sev.low{background:var(--low)}.sev.medium{background:var(--medium)}.sev.high{background:var(--high)}.sev.critical{background:var(--critical);color:#fff}
.inc{margin-top:16px;padding:20px 22px;border-radius:16px;background:var(--panel);border:1px solid var(--line)}
.inc-h{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px}
.inc-h h3{margin:0;font-size:18px}
.inc-meta{margin:8px 0 0;color:var(--ink2);font-size:13.5px}
.tl{list-style:none;margin:16px 0 0;padding:0 0 0 18px;border-left:2px solid var(--line)}
.tl li{position:relative;padding:6px 0 10px 12px}
.tl li::before{content:"";position:absolute;left:-25px;top:13px;width:10px;height:10px;border-radius:50%;background:var(--acc)}
.tl li.critical::before{background:var(--critical)}.tl li.high::before{background:var(--high)}.tl li.medium::before{background:var(--medium)}
.tl time{font:12.5px ui-monospace,Menlo,monospace;color:var(--ink2);margin-right:8px}
.tl .rid{font:12px ui-monospace,Menlo,monospace;color:var(--acc);margin-left:6px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:10px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font:500 11.5px ui-monospace,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase;color:var(--ink2)}
a{color:var(--acc)}
details{margin-top:6px}summary{cursor:pointer;color:var(--ink2);font-size:13px}
pre{margin:8px 0 0;padding:12px;border-radius:10px;background:#07081A;border:1px solid var(--line);overflow:auto;font:12px/1.5 ui-monospace,Menlo,monospace;color:#C9CBE6;white-space:pre-wrap;word-break:break-all}
.tags{display:flex;flex-wrap:wrap;gap:6px}
.tag{padding:2px 8px;border-radius:6px;background:#1E2045;font:12px ui-monospace,Menlo,monospace}
footer{margin-top:56px;color:var(--ink2);font-size:13px}
"""

e = html.escape  # tout ce qui vient des journaux est échappé : un journal peut contenir du HTML piégé


def _sev(s: str) -> str:
    return f'<span class="sev {s}">{e(SEV_FR[s])}</span>'


def _mitre(ids: list[str]) -> str:
    return '<span class="tags">' + "".join(
        f'<a class="tag" href="{e(mitre.url(t))}" title="{e(mitre.name(t))}" rel="noopener" target="_blank">{e(t)}</a>' for t in ids) + "</span>"


def to_html(alerts: list[Alert], events: list[Event], stats: dict, title: str = "Rapport Vigie") -> str:
    inc = incidents(alerts)
    by = Counter(a.severity for a in alerts)
    src = Counter(ev.source for ev in events)
    period = f"{events[0].ts:%d/%m/%Y %H:%M} → {events[-1].ts:%d/%m/%Y %H:%M}" if events else "—"
    cards = "".join(f'<div class="card"><b>{v}</b><span>{e(k)}</span></div>' for k, v in [
        ("événements analysés", len(events)), ("alertes", len(alerts)), ("incidents", len(inc)),
        ("critiques", by["critical"]), ("hautes", by["high"]), ("moyennes", by["medium"])])
    sources = " · ".join(f"{e(k)} : {v}" for k, v in sorted(src.items()))
    blocks = []
    for n, g in enumerate(inc, 1):
        who = ", ".join(sorted(g["ips"])) or ", ".join(sorted(g["users"])) or ", ".join(sorted(g["hosts"]))
        items = "".join(
            f'<li class="{a.severity}"><time>{a.when:%H:%M:%S}</time>{e(a.message)}<span class="rid">{e(a.rule.id)}</span></li>'
            for a in g["alerts"])
        accounts = f" · comptes : {e(', '.join(sorted(g['users'])))}" if g["users"] else ""
        blocks.append(f"""<section class="inc"><div class="inc-h">{_sev(g['severity'])}<h3>Incident {n} · {e(who)}</h3></div>
<p class="inc-meta">{g['first']:%d/%m %H:%M} → {g['last']:%H:%M} · {len(g['alerts'])} alertes{accounts}</p>
<div style="margin-top:10px">{_mitre(g['mitre'])}</div><ol class="tl">{items}</ol></section>""")
    rows = []
    for a in alerts:
        ev = "\n".join(f"{x.origin}  {x.raw}" for x in a.events[:8])
        rows.append(f"""<tr><td class="mono">{a.when:%d/%m %H:%M:%S}</td><td>{_sev(a.severity)}</td>
<td><b>{e(a.rule.title)}</b> <span class="mono" style="color:var(--acc)">{e(a.rule.id)}</span><br>{e(a.message)}
<details><summary>Preuves ({a.count} événements, {min(8, len(a.events))} affichés)</summary><pre>{e(ev)}</pre></details></td>
<td>{_mitre(a.rule.mitre)}</td></tr>""")
    files = ", ".join(f"{e(f['name'])} ({f['events']})" for f in stats.get("files", []))
    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>{e(title)}</title><style>{CSS}</style></head>
<body><main>
<p class="k">Vigie · rapport de détection</p>
<h1>{e(title)}</h1>
<p class="sub">Période : {e(period)} · Sources : {sources or '—'}</p>
<div class="cards">{cards}</div>
<h2>Incidents</h2>
<p class="sub">Les alertes liées (même adresse, même compte, même machine) sont regroupées et racontées dans l’ordre.</p>
{''.join(blocks) or '<p class="sub">Aucun incident.</p>'}
<h2>Toutes les alertes</h2>
<table><thead><tr><th>Heure</th><th>Gravité</th><th>Détection</th><th>MITRE ATT&amp;CK</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<footer>Généré par Vigie {e(__version__)} le {datetime.now():%d/%m/%Y à %H:%M} · fichiers : {files or '—'}</footer>
</main></body></html>
"""
