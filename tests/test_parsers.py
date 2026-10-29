"""Chaque format de journal est bien compris."""
import json

from vigie.parsers import firewall, linux_auth, web_access, windows


def test_ssh_failure_invalid_user():
    ev = linux_auth.parse_line("Oct 28 21:10:00 web01 sshd[2211]: Failed password for invalid user admin from 203.0.113.45 port 51122 ssh2", 2026)
    assert ev.action == "auth_failure"
    assert ev.user == "admin" and ev.src_ip == "203.0.113.45"
    assert ev.fields["invalid_user"] is True
    assert ev.ts.year == 2026 and ev.host == "web01"


def test_ssh_success_iso_timestamp():
    ev = linux_auth.parse_line("2026-10-28T21:14:05+01:00 web01 sshd[3000]: Accepted password for deploy from 203.0.113.45 port 52344 ssh2", 2026)
    assert ev.action == "auth_success" and ev.user == "deploy" and ev.fields["method"] == "password"


def test_sudo_and_accounts():
    sudo = linux_auth.parse_line("Oct 28 21:16:20 web01 sudo[100]:    deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash", 2026)
    assert sudo.action == "sudo" and sudo.user == "deploy" and sudo.fields == {"target_user": "root", "command": "/bin/bash"}
    add = linux_auth.parse_line("Oct 28 21:17:02 web01 useradd[1]: new user: name=backup2, UID=1007, GID=1007", 2026)
    assert add.action == "account_created" and add.user == "backup2"
    grp = linux_auth.parse_line("Oct 28 21:17:15 web01 usermod[2]: add 'backup2' to group 'sudo'", 2026)
    assert grp.action == "group_member_added" and grp.fields["group"] == "sudo"


def test_unknown_line_is_ignored():
    assert linux_auth.parse_line("Oct 28 08:17:00 web01 CRON[1]: pam_unix(cron:session): session opened", 2026) is None
    assert linux_auth.parse_line("ceci n'est pas un journal", 2026) is None


def test_firewall_block():
    ev = firewall.parse_line("Oct 28 20:58:00 fw01 kernel: [1.2] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.45 DST=192.0.2.10 PROTO=TCP SPT=61234 DPT=3389 SYN", 2026)
    assert ev.action == "conn_blocked" and ev.dst_port == 3389 and ev.src_ip == "203.0.113.45"


def test_web_request_is_url_decoded():
    line = '203.0.113.45 - - [28/Oct/2026:21:04:05 +0100] "GET /produits.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 512 "-" "sqlmap/1.8"'
    ev = web_access.parse_line(line)
    assert ev.fields["url"] == "/produits.php?id=1' OR '1'='1"
    assert ev.fields["path"] == "/produits.php" and ev.fields["status"] == 200
    assert ev.fields["user_agent"].startswith("sqlmap")


def test_windows_events():
    recs = [
        {"TimeCreated": "2026-10-28T21:30:00.1234567+01:00", "Id": 4625, "MachineName": "DC01", "EventData": {"TargetUserName": "administrateur", "IpAddress": "198.51.100.23", "LogonType": "3"}},
        {"TimeCreated": "2026-10-28T21:40:30+01:00", "Id": 4732, "MachineName": "DC01", "EventData": {"MemberName": "CN=svc-backup,CN=Users,DC=corp,DC=local", "TargetUserName": "Administrateurs"}},
        {"TimeCreated": "2026-10-28T21:45:00+01:00", "Id": 1102, "MachineName": "DC01", "EventData": {"SubjectUserName": "jdupont"}},
        {"autre": "chose"},
    ]
    events, skipped = windows.parse_text(json.dumps(recs))
    assert [e.action for e in events] == ["auth_failure", "group_member_added", "log_cleared"]
    assert events[0].src_ip == "198.51.100.23" and events[0].ts.microsecond == 123456
    assert events[1].user == "svc-backup" and events[1].fields["group"] == "Administrateurs"
    assert skipped == 1


def test_windows_local_logon_has_no_ip():
    rec = {"TimeCreated": "2026-10-28T10:00:00Z", "Id": 4624, "MachineName": "PC1", "EventData": {"TargetUserName": "alice", "IpAddress": "-"}}
    events, _ = windows.parse_text(json.dumps(rec))
    assert events[0].src_ip == ""
