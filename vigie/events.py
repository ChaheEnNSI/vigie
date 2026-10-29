"""Le format commun : chaque ligne de journal, quelle que soit sa source, devient un Event."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# champs « de premier niveau », accessibles directement dans les règles
CORE = ("ts", "source", "action", "host", "user", "src_ip", "dst_ip", "dst_port", "raw", "origin")


@dataclass
class Event:
    ts: datetime
    source: str  # linux | windows | web | firewall
    action: str  # auth_failure, auth_success, account_created, http_request, conn_blocked…
    host: str = ""
    user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    origin: str = ""  # fichier:ligne, pour remonter à la preuve

    def get(self, name: str) -> Any:
        """Lit un champ par son nom, qu'il soit standard ou propre à la source."""
        if name in CORE:
            return getattr(self, name)
        return self.fields.get(name)

    def to_dict(self) -> dict[str, Any]:
        d = {k: getattr(self, k) for k in CORE if k not in ("raw",)}
        d["ts"] = self.ts.isoformat()
        d.update(self.fields)
        d["raw"] = self.raw
        return {k: v for k, v in d.items() if v not in ("", None)}
