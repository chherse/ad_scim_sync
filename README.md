# ad-group-scim-sync

Liest die Mitglieder einer Active-Directory-Gruppe aus, speichert den Stand als JSON und schickt nur das **Delta** (neu / geändert / entfernt) per **SCIM 2.0** an einen Online-IdP. Gedacht für einen wöchentlichen Lauf über den Windows-Task-Scheduler (läuft aber überall, wo Python läuft).

## Funktionsweise

1. Mitglieder der Gruppe per LDAPS auslesen (Gruppe wird als Distinguished Name übergeben).
2. Mit dem letzten Stand in der State-JSON vergleichen. Schlüssel ist die `objectGUID`, daher überstehen Umbenennungen und UPN-Wechsel den Vergleich.
3. Delta an den IdP senden:

| Fall | SCIM-Aufruf |
|---|---|
| Neues Mitglied | `POST /Users` (bei `409` wird der vorhandene Benutzer gesucht und aktualisiert) |
| Attribut geändert | `PUT /Users/{id}` (bei `404` wird neu angelegt) |
| Mitglied entfernt | `PATCH /Users/{id}` mit `active=false` (Standard) oder `DELETE /Users/{id}` |

4. State-JSON atomar schreiben, aber nur für erfolgreich übertragene Änderungen. Fehlgeschlagene Operationen werden beim nächsten Lauf erneut versucht.

Übertragene Attribute: `externalId` (objectGUID), `userName` (UPN, sonst sAMAccountName), `displayName`, `name.givenName`, `name.familyName`, `emails[work]`, `active` (aus `userAccountControl`).

## Voraussetzungen

- Python 3.10 oder neuer
- Service-Account mit Leserechten auf die Gruppe und deren Benutzer
- LDAPS-Zugriff auf einen Domain Controller (Zertifikat muss vertrauenswürdig sein)
- SCIM-2.0-Endpunkt (HTTPS) und Bearer-Token des IdP

## Installation

```
python -m venv venv
venv\Scripts\activate          # Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

Abhängigkeiten aktuell halten und auf bekannte Schwachstellen prüfen, z. B.:

```
pip install -U -r requirements.txt
pip install pip-audit
pip-audit
```

## Konfiguration

`.env.example` nach `.env` kopieren und ausfüllen. Alternativ die Werte als Umgebungsvariablen setzen (diese haben Vorrang vor der Datei).

| Variable | Pflicht | Beschreibung |
|---|---|---|
| `GROUP_DN` | ja\* | DN der AD-Gruppe, z. B. `CN=SCIM-Sync,OU=Groups,DC=example,DC=local`. \*Entfällt, wenn der DN als Kommandozeilenargument übergeben wird (das Argument hat Vorrang) |
| `LDAP_SERVER` | ja | z. B. `ldaps://dc01.example.local` (Klartext-LDAP wird abgelehnt) |
| `LDAP_USER` | ja | `DOMAIN\user` (NTLM) oder `user@domain` (Simple Bind) |
| `LDAP_PASSWORD` | ja | Passwort des Service-Accounts |
| `LDAP_CA_FILE` | nein | CA-Bundle für die LDAPS-Prüfung |
| `SCIM_URL` | ja | Basis-URL, z. B. `https://idp.example.com/scim/v2` (nur HTTPS) |
| `SCIM_SECRET` | ja | Bearer-Token des IdP |
| `SCIM_CA_FILE` | nein | CA-Bundle für den IdP |
| `SCIM_REMOVE_MODE` | nein | `deactivate` (Standard) oder `delete` |
| `MAX_REMOVE_RATIO` | nein | Schutzgrenze für Entfernungen, Standard `0.3` |

Die `.env.example` enthält zu jedem Parameter einen Kommentar mit Bedeutung und Funktion. Kommentare müssen in einer eigenen Zeile mit `#` stehen, nicht hinter einem Wert.

**Wichtig:** `.env` enthält Zugangsdaten. Dateirechte auf den ausführenden Account beschränken und die Datei niemals committen (steht in der `.gitignore`).

## Nutzung

```
# Gruppe als Argument
python ad_group_scim_sync.py "CN=SCIM-Sync,OU=Groups,DC=example,DC=local" --env-file .env

# oder Gruppe über GROUP_DN in der .env
python ad_group_scim_sync.py --env-file .env
```

| Option | Wirkung |
|---|---|
| `--env-file PFAD` | Konfigurationsdatei im Format `KEY=VALUE` |
| `--state-file PFAD` | Pfad der State-JSON (Standard: `state/<hash-des-DN>.json`) |
| `--log-file PFAD` | Logdatei mit Rotation (Standard: `logs/ad_scim_sync.log`) |
| `--nested` | Verschachtelte Gruppen auflösen (LDAP_MATCHING_RULE_IN_CHAIN) |
| `--dry-run` | Nur das Delta anzeigen, nichts senden und nichts speichern |
| `--force` | Sicherheitsgrenze (siehe unten) ignorieren |

Empfehlung: Beim ersten Mal mit `--dry-run` starten. Der erste echte Lauf sendet alle Mitglieder als „neu“.

### Exit-Codes

| Code | Bedeutung |
|---|---|
| 0 | Erfolgreich |
| 1 | Einzelne SCIM-Operationen fehlgeschlagen (werden wiederholt) |
| 2 | Abbruch durch Fehler oder Sicherheitsgrenze |

## Task-Scheduler (Windows)

Der Task-Scheduler setzt kein Arbeitsverzeichnis. Deshalb für State und Log **absolute Pfade** angeben:

```
schtasks /Create /TN "AD-SCIM-Sync" /SC WEEKLY /D MON /ST 03:00 /RU "EXAMPLE\svc-scim" /RP * ^
  /TR "\"C:\scim\venv\Scripts\python.exe\" \"C:\scim\ad_group_scim_sync.py\" \"CN=SCIM-Sync,OU=Groups,DC=example,DC=local\" --env-file C:\scim\.env --state-file C:\scim\state\sync.json --log-file C:\scim\logs\sync.log"
```

Der Account braucht das Recht „Als Batchauftrag anmelden“.

## Sicherheitsmechanismen

- **Schutz vor leeren Antworten:** Liefert die Gruppe 0 Mitglieder, obwohl der State welche kennt, bricht der Lauf mit Code 2 ab.
- **Schutz vor Massenentfernung:** Würden mindestens 5 Mitglieder und mehr als `MAX_REMOVE_RATIO` des Bestands entfernt, bricht der Lauf ab. Mit `--force` lässt sich das bewusst übergehen.
- Entfernte Benutzer werden standardmäßig nur deaktiviert, nicht gelöscht.
- Zertifikate werden bei LDAPS und SCIM geprüft, `http://` und `ldap://` werden abgelehnt.
- Das SCIM-Secret wird nicht geloggt.
- Die State-JSON enthält Personendaten (Name, E-Mail, UPN) und gehört nicht in ein Repository.

## State-Datei

```json
{
  "version": 1,
  "group_dn": "CN=SCIM-Sync,OU=Groups,DC=example,DC=local",
  "updated": "2026-11-05T03:00:12+00:00",
  "members": {
    "<objectGUID>": {
      "attrs": { "userName": "...", "mail": "...", "active": true },
      "scim_id": "<ID des IdP>"
    }
  }
}
```

Die State-Datei ist an eine Gruppe gebunden. Für mehrere Gruppen das Skript mehrfach mit je eigenem DN aufrufen (der Standardpfad ist pro DN eindeutig).

## Bekannte Einschränkungen

- Nur User-Objekte, keine SCIM-Groups.
- Updates laufen per `PUT` mit vollem Objekt. Manche IdPs erwarten `PATCH` oder haben Besonderheiten bei `name` und `emails`. Gegen Testbenutzer prüfen.
- Benutzer, deren Primary Group die Zielgruppe ist, werden über `memberOf` nicht erfasst.
- Es gibt keine Sperre gegen parallele Läufe.
- Nicht gegen einen konkreten IdP getestet.

## Autor

Christoph Herse, <christoph.herse@vaps.de>

## Lizenz

[MIT License](LICENSE), Copyright (c) 2026 Christoph Herse. Die Software wird ohne Gewährleistung und ohne Haftung bereitgestellt („as is“).
