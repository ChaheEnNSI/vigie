# Vigie

[![tests](https://github.com/ChaheEnNSI/vigie/actions/workflows/ci.yml/badge.svg)](https://github.com/ChaheEnNSI/vigie/actions/workflows/ci.yml)

Un mini SIEM en Python que j'ai codé pour comprendre comment on repère une attaque dans des logs.

Il lit des logs Linux (auth.log), de pare-feu (UFW), de serveur web (Apache/Nginx) et des événements Windows exportés en JSON. Il passe dessus des règles de détection écrites en YAML, puis il regroupe les alertes qui vont ensemble en incidents.

J'ai écrit une page qui explique comment je l'ai construit : https://chaheennsi.github.io/vigie/

## Pourquoi

Pendant mon alternance chez Anetys j'ai utilisé ELK pour surveiller le réseau. Je voyais les alertes et les dashboards, mais pas vraiment ce qui se passait derrière. Je voulais savoir comment on passe de milliers de lignes de logs à « quelqu'un essaie de forcer le SSH ». Le plus simple pour comprendre, c'était d'en coder un petit moi-même.

## Essayer

Il faut Python 3.10 ou plus.

```bash
git clone https://github.com/ChaheEnNSI/vigie
cd vigie
pip install -e .
python -m vigie scan samples --year 2026 --tz Europe/Paris
```

Le dossier `samples/` contient une journée de logs que j'ai générée avec `samples/generate.py` : du trafic normal (connexions, fautes de frappe, bots d'Internet...) avec deux attaques cachées dedans. Ce que ça donne :

```text
1887 événements lus (24 lignes ignorées)

28/10 20:58:00  MOYENNE   VIG-014  40 ports différents testés par 203.0.113.45 en 39 s
28/10 21:01:30  MOYENNE   VIG-013  Scanner détecté depuis 203.0.113.45 (61 requêtes)
28/10 21:04:05  HAUTE     VIG-010  30 requêtes d'injection SQL depuis 203.0.113.45 (ex. /produits.php)
...
28/10 21:14:05  CRITIQUE  VIG-003  Connexion réussie depuis 203.0.113.45 après une série d'échecs (31 événements en 4 min 05 s)
...
28/10 21:45:00  CRITIQUE  VIG-007  Journal de sécurité effacé sur DC01.corp.local par jdupont

18 alertes (3 critique · 8 haute · 7 moyenne)

2 incidents
  1. CRITIQUE  28/10 20:58 → 21:17  203.0.113.45 · 10 alertes · comptes : backup2, deploy
  2. CRITIQUE  28/10 21:20 → 21:45  198.51.100.23 · 8 alertes · comptes : jdupont, svc-backup
```

Avec `-f html -o rapport.html` on obtient un rapport HTML (incidents, chronologie, lignes de logs en preuve). Celui des logs de démo est en ligne [ici](https://chaheennsi.github.io/portfolio2026/vigie/rapport.html).

Les IP des attaquants sont dans les plages réservées à la documentation (203.0.113.0/24, 198.51.100.0/24), ce ne sont pas de vraies adresses.

## Les règles

| Règle | Ce qu'elle détecte | Gravité | MITRE ATT&CK |
|---|---|---|---|
| VIG-001 | Force brute SSH (8 échecs en 5 min depuis la même IP) | haute | T1110.001 |
| VIG-002 | Password spraying (5 comptes différents en 10 min) | haute | T1110.003 |
| VIG-003 | Connexion réussie après une série d'échecs | critique | T1110, T1078 |
| VIG-004 | Compte Windows visé (10 échecs en 10 min) | moyenne | T1110 |
| VIG-005 | Ajout à un groupe admin (Admins du domaine, sudo...) | haute | T1098 |
| VIG-006 | Création de compte | moyenne | T1136 |
| VIG-007 | Journal de sécurité Windows effacé | critique | T1070.001 |
| VIG-008 | Service installé depuis un dossier bizarre | haute | T1543.003 |
| VIG-009 | PowerShell avec une commande encodée | haute | T1059.001, T1027 |
| VIG-010 | Injection SQL | haute | T1190 |
| VIG-011 | XSS | moyenne | T1190, T1059.007 |
| VIG-012 | Traversée de répertoires (`../`, `/etc/passwd`) | haute | T1190, T1083 |
| VIG-013 | Scanner web (sqlmap, Nikto...) | moyenne | T1595.002 |
| VIG-014 | Scan de ports (15 ports en 2 min) | moyenne | T1046 |
| VIG-015 | Shell root ouvert avec sudo | moyenne | T1548.003 |

Une règle, c'est un fichier YAML. Par exemple la force brute SSH :

```yaml
id: VIG-001
title: Force brute SSH
severity: high
mitre: [T1110.001]
match:
  source: linux
  action: auth_failure
threshold:
  group_by: src_ip
  count: 8
  window: 5m
message: "{count} échecs de connexion SSH depuis {src_ip} en {duration}"
```

Il y a trois types de règles :

- **simple** : un seul événement suffit (un journal Windows effacé par exemple)
- **seuil** : X événements dans une fenêtre de temps, ou X valeurs différentes (8 échecs en 5 min, 5 comptes différents...)
- **séquence** : un événement puis un autre pour la même IP (des échecs puis une connexion qui réussit)

Les règles fournies sont dans `vigie/detections/`. Pour utiliser les tiennes : `-r mon-dossier/`. `python -m vigie rules` liste celles qui sont chargées.

## Comment c'est organisé

```text
vigie/parsers/      un fichier par type de log
vigie/events.py     le format commun (Event)
vigie/rules.py      chargement et vérification des règles YAML
vigie/engine.py     le moteur : seuils, séquences, regroupement en incidents
vigie/report.py     sortie terminal, JSON et HTML
vigie/detections/   les 15 règles
samples/            les logs de démo et le script qui les génère
tests/
```

Chaque parser transforme une ligne en `Event` (heure, source, action, utilisateur, IP...). Après ça, les règles ne savent plus d'où vient la ligne. C'est ce qui permet à VIG-002 et VIG-003 de marcher à la fois sur du SSH et sur des connexions Windows.

Pour avoir des logs Windows, il y a un script PowerShell qui exporte les bons événements (4624, 4625, 4688, 4720, 4728, 4732, 4756, 1102, 7045) en JSON :

```powershell
.\scripts\export-windows-security.ps1 -Heures 24 -Sortie .\windows-security.json
```

## Ce qui m'a posé problème

- **Les dates.** Syslog n'écrit pas l'année, et les événements Windows peuvent être exportés en UTC alors que les logs Linux sont en heure locale. Si on compare sans faire attention, il y a une heure d'écart et une séquence Linux puis Windows ne se déclenche jamais. D'où les options `--year` et `--tz`.
- **Le JSON de PowerShell.** Il peut commencer par un BOM et `json.loads` refuse de le lire. Et selon la version de PowerShell, les dates sont au format `/Date(...)/` ou en ISO avec 7 décimales.
- **Les fausses alertes.** Quelqu'un qui se trompe deux fois de mot de passe puis se connecte ne doit pas déclencher VIG-003. C'est pour ça que les logs de démo contiennent beaucoup de bruit normal, et qu'un test vérifie qu'aucune alerte ne sort à part les 18 attendues.
- **Les doublons.** Un scanner qui envoie 300 requêtes ne doit pas faire 300 alertes. Une même règle sur la même IP fait une seule alerte qui se met à jour tant que l'attaque continue.
- **Le rapport HTML.** Il affiche des URL et des user-agents écrits par l'attaquant. Sans échappement, le rapport lui-même devient une faille XSS. Tout est échappé, la page bloque les scripts (CSP), et il y a un test qui glisse un `<script>` dans un log pour vérifier.

## Tests

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

Le test le plus important (`tests/test_scenario.py`) lance Vigie sur les logs de démo et vérifie que les 18 étapes des deux attaques sont trouvées, sans aucune alerte en plus. La CI GitHub Actions lance tout ça à chaque push, sur Python 3.10, 3.12 et 3.13.

## Limites

C'est un projet perso pour apprendre, pas un outil de production :

- les logs de démo sont générés, pas issus de vraies attaques, et les seuils sont réglés pour eux
- Vigie lit des fichiers, il ne surveille pas en temps réel
- la corrélation reste simple (même IP, même compte, ou même machine dans la demi-heure)

Ce que j'aimerais ajouter : un mode `--follow` pour lire les logs en direct, l'import de règles [Sigma](https://github.com/SigmaHQ/sigma), les logs Sysmon, et surtout le tester sur un vrai labo avec des attaques rejouées.

## Licence

MIT
