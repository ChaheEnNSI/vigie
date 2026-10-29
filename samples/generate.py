"""Génère les journaux de démonstration : une journée normale… et deux attaques cachées dedans.

Tout est déterministe (graine fixe) : les tests peuvent vérifier précisément ce que Vigie doit trouver.
Les adresses des attaquants viennent des plages réservées à la documentation (RFC 5737).

    python samples/generate.py
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent
R = random.Random(2026)
DAY = datetime(2026, 10, 28)
TZ = "+01:00"  # Paris, heure d'hiver

ATTACKER_WEB = "203.0.113.45"   # scanne, attaque le site, puis force l'accès SSH
ATTACKER_SPRAY = "198.51.100.23"  # pulvérise des mots de passe, puis prend la main sur le contrôleur de domaine

EMPLOYEES = ["alice", "bob", "carla", "deploy", "mmartin"]
LAN = [f"10.0.1.{i}" for i in range(10, 60)]
INTERNET = [f"{R.randint(11, 223)}.{R.randint(0, 255)}.{R.randint(0, 255)}.{R.randint(1, 254)}" for _ in range(160)]


def at(h, m, s=0):
    return DAY + timedelta(hours=h, minutes=m, seconds=s)


def syslog(ts: datetime, host: str, prog: str, msg: str) -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {host} {prog}[{R.randint(900, 32000)}]: {msg}"


def kernel(ts: datetime, host: str, msg: str) -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {host} kernel: [{R.randint(10000, 99999)}.{R.randint(100000, 999999)}] {msg}"


# ------------------------------------------------------------------ auth.log (serveur web01)
def auth_log() -> list[tuple[datetime, str]]:
    L = []
    for _ in range(140):  # connexions normales, parfois une faute de frappe avant
        ts = at(R.randint(8, 19), R.randint(0, 59), R.randint(0, 59))
        user, ip = R.choice(EMPLOYEES), R.choice(LAN)
        if R.random() < .12:
            for _ in range(R.randint(1, 2)):
                L.append((ts, syslog(ts, "web01", "sshd", f"Failed password for {user} from {ip} port {R.randint(40000, 65000)} ssh2")))
                ts += timedelta(seconds=R.randint(3, 9))
        method = "publickey" if R.random() < .7 else "password"
        L.append((ts, syslog(ts, "web01", "sshd", f"Accepted {method} for {user} from {ip} port {R.randint(40000, 65000)} ssh2")))
    for _ in range(40):  # sudo du quotidien
        ts = at(R.randint(8, 19), R.randint(0, 59), R.randint(0, 59))
        cmd = R.choice(["/usr/bin/systemctl restart nginx", "/usr/bin/apt update", "/usr/bin/tail -n 50 /var/log/nginx/error.log", "/usr/bin/journalctl -u php8.2-fpm"])
        L.append((ts, syslog(ts, "web01", "sudo", f"   {R.choice(['alice', 'deploy'])} : TTY=pts/{R.randint(0, 3)} ; PWD=/home ; USER=root ; COMMAND={cmd}")))
    for h in range(0, 24):  # lignes que Vigie ne lit pas (et le dit)
        ts = at(h, 17)
        L.append((ts, syslog(ts, "web01", "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")))
    # attaque 1 : force brute SSH, puis le mot de passe de « deploy » tombe
    ts = at(21, 10)
    for user in ["root"] * 15 + ["admin"] * 6 + ["deploy"] * 9:
        inv = "invalid user " if user == "admin" else ""
        L.append((ts, syslog(ts, "web01", "sshd", f"Failed password for {inv}{user} from {ATTACKER_WEB} port {R.randint(40000, 65000)} ssh2")))
        ts += timedelta(seconds=R.randint(4, 9))
    ts = at(21, 14, 5)
    L.append((ts, syslog(ts, "web01", "sshd", f"Accepted password for deploy from {ATTACKER_WEB} port 52344 ssh2")))
    ts = at(21, 16, 20)
    L.append((ts, syslog(ts, "web01", "sudo", "   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")))
    ts = at(21, 17, 2)
    L.append((ts, syslog(ts, "web01", "useradd", "new user: name=backup2, UID=1007, GID=1007, home=/home/backup2, shell=/bin/bash, from=/dev/pts/1")))
    ts = at(21, 17, 15)
    L.append((ts, syslog(ts, "web01", "usermod", "add 'backup2' to group 'sudo'")))
    # attaque 2 : pulvérisation de mots de passe, lente, sur huit comptes
    ts = at(21, 20)
    for user in ["alice", "bob", "carla", "deploy", "admin", "test", "oracle", "postgres", "alice", "mmartin"]:
        inv = "invalid user " if user in ("admin", "test", "oracle", "postgres") else ""
        L.append((ts, syslog(ts, "web01", "sshd", f"Failed password for {inv}{user} from {ATTACKER_SPRAY} port {R.randint(40000, 65000)} ssh2")))
        ts += timedelta(seconds=R.randint(50, 60))
    return L


# ------------------------------------------------------------------ ufw.log (pare-feu fw01)
def ufw_log() -> list[tuple[datetime, str]]:
    L = []
    for ip in INTERNET:  # le bruit de fond d'Internet : quelques ports chacun
        ts = at(R.randint(0, 23), R.randint(0, 59), R.randint(0, 59))
        for port in R.sample([22, 23, 25, 445, 1433, 3306, 3389, 5900, 8080], R.randint(1, 3)):
            L.append((ts, kernel(ts, "fw01", f"[UFW BLOCK] IN=eth0 OUT= MAC= SRC={ip} DST=192.0.2.10 LEN=44 TOS=0x00 PREC=0x00 TTL=241 ID=54321 PROTO=TCP SPT={R.randint(1024, 65535)} DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0")))
            ts += timedelta(seconds=R.randint(1, 30))
    # attaque 1, étape 0 : la reconnaissance (40 ports en une quarantaine de secondes)
    ts = at(20, 58)
    for port in R.sample(range(1, 10000), 40):
        L.append((ts, kernel(ts, "fw01", f"[UFW BLOCK] IN=eth0 OUT= MAC= SRC={ATTACKER_WEB} DST=192.0.2.10 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID={R.randint(1000, 65000)} PROTO=TCP SPT=61234 DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0")))
        ts += timedelta(seconds=1)
    return L


# ------------------------------------------------------------------ access.log (site web)
PAGES = ["/", "/produits.php?id={n}", "/contact", "/a-propos", "/recherche?q={w}", "/css/style.css", "/js/app.js", "/img/logo.png", "/panier", "/telecharger.php?fichier=catalogue-{n}.pdf"]
WORDS = ["routeur", "switch", "cable", "pare-feu", "wifi", "onduleur"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
       "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"]


def access(ts: datetime, ip: str, path: str, status: int, ua: str, size: int | None = None) -> str:
    return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0100] "GET {path} HTTP/1.1" {status} {size or R.randint(300, 24000)} "-" "{ua}"'


def access_log() -> list[tuple[datetime, str]]:
    L = []
    for _ in range(900):
        ts = at(R.randint(7, 23), R.randint(0, 59), R.randint(0, 59))
        page = R.choice(PAGES).format(n=R.randint(1, 60), w=R.choice(WORDS))
        status = 404 if R.random() < .04 else 200
        L.append((ts, access(ts, R.choice(INTERNET[:80]), page, status, R.choice(UAS))))
    ip = ATTACKER_WEB
    ts = at(21, 1, 30)  # Nikto passe le site au crible
    for path in ["/admin/", "/.git/config", "/phpmyadmin/", "/backup.zip", "/.env", "/wp-login.php", "/server-status", "/config.php.bak",
                 "/admin/login.php", "/test.php", "/info.php", "/db.sql", "/.htaccess", "/cgi-bin/test.cgi", "/old/", "/dev/", "/api/v1/users",
                 "/install.php", "/README.md", "/composer.json", "/vendor/", "/logs/", "/debug", "/console", "/actuator/health"]:
        L.append((ts, access(ts, ip, path, R.choice([404, 404, 403]), "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:007105)", 220)))
        ts += timedelta(seconds=R.randint(1, 3))
    ts = at(21, 4)  # sqlmap s'acharne sur un paramètre
    for payload in ["1'", "1 AND 1=1", "1' OR '1'='1", "1 OR 1=1-- -", "1' AND SLEEP(5)-- -", "1 UNION ALL SELECT NULL-- -",
                    "1 UNION ALL SELECT NULL,NULL-- -", "1 UNION ALL SELECT NULL,NULL,NULL-- -", "1 UNION SELECT table_name,2,3 FROM information_schema.tables-- -",
                    "1 UNION SELECT login,password,3 FROM utilisateurs-- -", "1'--", "1); DROP TABLE produits;--"] * 3:
        q = payload.replace(" ", "%20").replace("'", "%27")
        L.append((ts, access(ts, ip, f"/produits.php?id={q}", R.choice([200, 500]), "sqlmap/1.8.4#stable (https://sqlmap.org)")))
        ts += timedelta(seconds=R.randint(1, 4))
    ua = UAS[0]
    ts = at(21, 6, 10)  # puis quelques essais à la main
    for path in ["/recherche?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "/recherche?q=%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E", "/contact?nom=%3Csvg%2Fonload%3Dalert(1)%3E"]:
        L.append((ts, access(ts, ip, path, 200, ua)))
        ts += timedelta(seconds=R.randint(8, 20))
    ts = at(21, 7)
    for path in ["/telecharger.php?fichier=../../../../etc/passwd", "/telecharger.php?fichier=..%2F..%2F..%2F..%2Fetc%2Fshadow", "/telecharger.php?fichier=....//....//etc/passwd"]:
        L.append((ts, access(ts, ip, path, R.choice([200, 403]), ua)))
        ts += timedelta(seconds=R.randint(5, 12))
    return L


# ------------------------------------------------------------------ journal de sécurité Windows (DC01)
def win(ts: datetime, eid: int, data: dict) -> dict:
    return {"TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{R.randint(0, 9999999):07d}" + TZ, "Id": eid, "MachineName": "DC01.corp.local", "EventData": data}


def windows_log() -> list[tuple[datetime, dict]]:
    L = []
    users = ["alice", "jdupont", "mmartin", "carla", "bob"]
    for _ in range(260):
        ts = at(R.randint(7, 19), R.randint(0, 59), R.randint(0, 59))
        u, ip = R.choice(users), R.choice(LAN)
        if R.random() < .1:
            for _ in range(R.randint(1, 2)):
                L.append((ts, win(ts, 4625, {"TargetUserName": u, "TargetDomainName": "CORP", "LogonType": "3", "IpAddress": ip, "Status": "0xc000006d"})))
                ts += timedelta(seconds=R.randint(4, 15))
        L.append((ts, win(ts, 4624, {"TargetUserName": u, "TargetDomainName": "CORP", "LogonType": R.choice(["2", "3", "3", "3"]), "IpAddress": ip})))
    # attaque 2 : le compte administrateur est martelé, puis jdupont tombe
    ts = at(21, 30)
    for _ in range(14):
        L.append((ts, win(ts, 4625, {"TargetUserName": "administrateur", "TargetDomainName": "CORP", "LogonType": "3", "IpAddress": ATTACKER_SPRAY, "Status": "0xc000006a"})))
        ts += timedelta(seconds=R.randint(12, 20))
    ts = at(21, 36, 12)
    L.append((ts, win(ts, 4624, {"TargetUserName": "jdupont", "TargetDomainName": "CORP", "LogonType": "10", "IpAddress": ATTACKER_SPRAY})))
    ts = at(21, 38, 40)
    L.append((ts, win(ts, 4688, {"SubjectUserName": "jdupont", "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                 "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"})))
    ts = at(21, 40, 5)
    L.append((ts, win(ts, 4720, {"TargetUserName": "svc-backup", "TargetDomainName": "CORP", "SubjectUserName": "jdupont"})))
    ts = at(21, 40, 30)
    L.append((ts, win(ts, 4732, {"MemberName": "CN=svc-backup,CN=Users,DC=corp,DC=local", "TargetUserName": "Administrateurs", "SubjectUserName": "jdupont"})))
    ts = at(21, 42, 10)
    L.append((ts, win(ts, 7045, {"ServiceName": "WinUpdateSvc", "ImagePath": "C:\\Users\\Public\\winupdate.exe", "ServiceType": "user mode service", "StartType": "auto start"})))
    ts = at(21, 45)
    L.append((ts, win(ts, 1102, {"SubjectUserName": "jdupont", "SubjectDomainName": "CORP"})))
    return L


# ------------------------------------------------------------------ ce que Vigie doit trouver
EXPECTED = [
    ("VIG-014", ATTACKER_WEB), ("VIG-013", ATTACKER_WEB), ("VIG-010", ATTACKER_WEB), ("VIG-011", ATTACKER_WEB), ("VIG-012", ATTACKER_WEB),
    ("VIG-001", ATTACKER_WEB), ("VIG-003", ATTACKER_WEB), ("VIG-015", "deploy"), ("VIG-006", "backup2"), ("VIG-005", "backup2"),
    ("VIG-002", ATTACKER_SPRAY), ("VIG-004", "administrateur"), ("VIG-003", ATTACKER_SPRAY), ("VIG-009", "jdupont"),
    ("VIG-006", "svc-backup"), ("VIG-005", "svc-backup"), ("VIG-008", "DC01.corp.local"), ("VIG-007", "jdupont"),
]


def write(name: str, rows: list[tuple[datetime, str]]) -> None:
    rows.sort(key=lambda r: r[0])
    (OUT / name).write_text("\n".join(r for _, r in rows) + "\n", encoding="utf-8")


def main() -> None:
    write("auth.log", auth_log())
    write("ufw.log", ufw_log())
    write("access.log", access_log())
    w = windows_log()
    w.sort(key=lambda r: r[0])
    (OUT / "windows-security.json").write_text(json.dumps([r for _, r in w], ensure_ascii=False, indent=1), encoding="utf-8")
    (OUT.parent / "tests" / "expected.json").write_text(json.dumps([{"rule": r, "key": k} for r, k in EXPECTED], indent=1), encoding="utf-8")
    print("journaux générés dans", OUT)


if __name__ == "__main__":
    main()
