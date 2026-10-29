"""Les techniques MITRE ATT&CK utilisées par les règles (nom et lien vers la fiche officielle)."""

TECHNIQUES = {
    "T1027": "Obfuscated Files or Information",
    "T1046": "Network Service Discovery",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1078": "Valid Accounts",
    "T1083": "File and Directory Discovery",
    "T1098": "Account Manipulation",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1136": "Create Account",
    "T1190": "Exploit Public-Facing Application",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
}


def name(tid: str) -> str:
    return TECHNIQUES.get(tid, tid)


def url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
