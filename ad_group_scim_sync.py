"""
AD-Gruppe -> JSON-State -> SCIM-Delta an einen IdP.

Autor:   Christoph Herse <christoph.herse@vaps.de>
Lizenz:  MIT (siehe LICENSE)

Ablauf pro Lauf:
  1. Mitglieder der Gruppe (Distinguished Name als Argument) per LDAPS auslesen
  2. Mit dem letzten Stand (JSON-Datei) vergleichen -> added / changed / removed
  3. Delta per SCIM 2.0 an den IdP schicken
  4. Neuen Stand in die JSON-Datei schreiben (nur erfolgreich uebertragene Aenderungen)

Konfiguration ausschliesslich ueber Umgebungsvariablen (oder --env-file):
  GROUP_DN           DN der AD-Gruppe (alternativ als Kommandozeilenargument, das Vorrang hat)
  LDAP_SERVER        z. B. ldaps://dc01.example.local
  LDAP_USER          DOMAIN\\svc-scim  oder  svc-scim@example.local
  LDAP_PASSWORD
  LDAP_CA_FILE       (optional) Pfad zu CA-Bundle fuer LDAPS
  SCIM_URL           z. B. https://idp.example.com/scim/v2
  SCIM_SECRET        Bearer-Token des IdP
  SCIM_CA_FILE       (optional) CA-Bundle fuer den IdP
  SCIM_REMOVE_MODE   deactivate (Default) | delete
  MAX_REMOVE_RATIO   (optional, Default 0.3) Sicherheitsgrenze gegen Massenloeschung

Exit-Codes: 0 = ok, 1 = einzelne SCIM-Operationen fehlgeschlagen, 2 = Abbruch (Fehler/Sicherheitsgrenze)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import ssl
import sys
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import requests
from ldap3 import NTLM, SIMPLE, SUBTREE, BASE, Connection, Server, Tls, NONE
from ldap3.utils.conv import escape_filter_chars
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("ad_scim_sync")

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
LDAP_ATTRS = [
    "objectGUID", "sAMAccountName", "userPrincipalName", "mail",
    "givenName", "sn", "displayName", "userAccountControl",
]
UAC_ACCOUNTDISABLE = 0x2
HTTP_TIMEOUT = 30


# --------------------------------------------------------------------------- #
# Konfiguration
# --------------------------------------------------------------------------- #
def load_env_file(path: str) -> None:
    """Minimaler KEY=VALUE-Parser. Bereits gesetzte Umgebungsvariablen gewinnen."""
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def need(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Umgebungsvariable {name} fehlt")
    return value


# --------------------------------------------------------------------------- #
# LDAP
# --------------------------------------------------------------------------- #
def _s(raw: dict[str, list], name: str) -> str | None:
    vals = raw.get(name) or []
    if not vals:
        return None
    v = vals[0]
    s = v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)
    return s.strip() or None


def base_dn_from(dn: str) -> str:
    parts = [p.strip() for p in dn.split(",") if p.strip().upper().startswith("DC=")]
    if not parts:
        raise SystemExit("Aus dem Gruppen-DN konnte keine Base-DN (DC=...) abgeleitet werden")
    return ",".join(parts)


def fetch_members(group_dn: str, nested: bool) -> dict[str, dict[str, Any]]:
    server_url = need("LDAP_SERVER")
    if not server_url.lower().startswith("ldaps://"):
        raise SystemExit("LDAP_SERVER muss ldaps:// verwenden (Klartext-LDAP wird nicht unterstuetzt)")

    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=os.environ.get("LDAP_CA_FILE") or None)
    server = Server(server_url, tls=tls, get_info=NONE, connect_timeout=15)

    user = need("LDAP_USER")
    auth = NTLM if "\\" in user else SIMPLE
    members: dict[str, dict[str, Any]] = {}

    with Connection(server, user=user, password=need("LDAP_PASSWORD"),
                    authentication=auth, auto_bind=True, receive_timeout=60) as conn:
        # Existiert die Gruppe? Sonst wuerde die Suche still 0 Treffer liefern.
        if not conn.search(group_dn, "(objectClass=group)", search_scope=BASE, attributes=["cn"]) \
                or not conn.entries:
            raise RuntimeError(f"Gruppe nicht gefunden: {group_dn}")

        esc = escape_filter_chars(group_dn)
        clause = f"(memberOf:1.2.840.113556.1.4.1941:={esc})" if nested else f"(memberOf={esc})"
        flt = f"(&(objectCategory=person)(objectClass=user){clause})"

        gen = conn.extend.standard.paged_search(
            base_dn_from(group_dn), flt, search_scope=SUBTREE,
            attributes=LDAP_ATTRS, paged_size=500, generator=True,
        )
        for entry in gen:
            if entry.get("type") != "searchResEntry":
                continue
            raw = entry["raw_attributes"]
            guid_raw = (raw.get("objectGUID") or [None])[0]
            if not guid_raw:
                continue
            guid = str(uuid.UUID(bytes_le=bytes(guid_raw)))
            uac = int(_s(raw, "userAccountControl") or 0)
            upn = _s(raw, "userPrincipalName")
            sam = _s(raw, "sAMAccountName")
            user_name = upn or sam
            if not user_name:
                log.warning("Benutzer %s ohne UPN/sAMAccountName uebersprungen", guid)
                continue
            members[guid] = {
                "userName": user_name,
                "sam": sam,
                "mail": _s(raw, "mail"),
                "givenName": _s(raw, "givenName"),
                "familyName": _s(raw, "sn"),
                "displayName": _s(raw, "displayName"),
                "active": not (uac & UAC_ACCOUNTDISABLE),
            }
    return members


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
def load_state(path: Path, group_dn: str) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "group_dn": group_dn, "members": {}}
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("group_dn") != group_dn:
        raise SystemExit(f"State-Datei {path} gehoert zu einer anderen Gruppe: {state.get('group_dn')}")
    return state


def save_state(path: Path, state: dict[str, Any]) -> None:
    state["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)  # atomar


def compute_delta(old: dict[str, Any], current: dict[str, Any]):
    added = sorted(current.keys() - old.keys())
    removed = sorted(old.keys() - current.keys())
    changed = sorted(g for g in current.keys() & old.keys() if old[g]["attrs"] != current[g])
    return added, changed, removed


# --------------------------------------------------------------------------- #
# SCIM
# --------------------------------------------------------------------------- #
class ScimError(Exception):
    pass


class ScimNotFound(ScimError):
    pass


class ScimClient:
    def __init__(self, base_url: str, secret: str, remove_mode: str) -> None:
        if not base_url.lower().startswith("https://"):
            raise SystemExit("SCIM_URL muss https:// verwenden")
        self.base = base_url.rstrip("/")
        self.remove_mode = remove_mode
        s = requests.Session()
        s.headers.update({
            "Authorization": f"Bearer {secret}",
            "Accept": "application/scim+json, application/json",
            "Content-Type": "application/scim+json",
        })
        # POST bewusst nicht automatisch wiederholen (Duplikate); 409 wird separat behandelt.
        retry = Retry(total=3, backoff_factor=1.5, status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=frozenset({"GET", "PUT", "PATCH", "DELETE"}),
                      respect_retry_after_header=True)
        s.mount("https://", HTTPAdapter(max_retries=retry))
        s.verify = os.environ.get("SCIM_CA_FILE") or True
        self.s = s

    @staticmethod
    def body(guid: str, a: dict[str, Any]) -> dict[str, Any]:
        b: dict[str, Any] = {
            "schemas": [USER_SCHEMA],
            "externalId": guid,
            "userName": a["userName"],
            "active": a["active"],
        }
        if a.get("displayName"):
            b["displayName"] = a["displayName"]
        name = {k: v for k, v in (("givenName", a.get("givenName")),
                                  ("familyName", a.get("familyName"))) if v}
        if name:
            b["name"] = name
        if a.get("mail"):
            b["emails"] = [{"value": a["mail"], "type": "work", "primary": True}]
        return b

    def _req(self, method: str, path: str, **kw) -> requests.Response:
        try:
            r = self.s.request(method, f"{self.base}{path}", timeout=HTTP_TIMEOUT, **kw)
        except requests.RequestException as exc:
            raise ScimError(f"{method} {path}: {exc.__class__.__name__}") from exc
        return r

    @staticmethod
    def _fail(r: requests.Response, what: str) -> ScimError:
        return ScimError(f"{what}: HTTP {r.status_code} {r.text[:300]!r}")

    def find_id(self, guid: str) -> str | None:
        r = self._req("GET", "/Users", params={"filter": f'externalId eq "{guid}"'})
        if r.status_code != 200:
            raise self._fail(r, "Suche")
        res = r.json().get("Resources") or []
        return res[0]["id"] if res else None

    def create(self, guid: str, a: dict[str, Any]) -> str:
        r = self._req("POST", "/Users", data=json.dumps(self.body(guid, a)))
        if r.status_code == 201:
            return r.json()["id"]
        if r.status_code == 409:  # existiert schon -> uebernehmen und aktualisieren
            sid = self.find_id(guid)
            if not sid:
                raise self._fail(r, "Create (409, Benutzer nicht auffindbar)")
            self.update(sid, guid, a)
            return sid
        raise self._fail(r, f"Create {a['userName']}")

    def update(self, scim_id: str, guid: str, a: dict[str, Any]) -> None:
        r = self._req("PUT", f"/Users/{scim_id}", data=json.dumps(self.body(guid, a)))
        if r.status_code == 404:
            raise ScimNotFound(scim_id)
        if r.status_code not in (200, 204):
            raise self._fail(r, f"Update {a['userName']}")

    def remove(self, scim_id: str, user_name: str) -> None:
        if self.remove_mode == "delete":
            r = self._req("DELETE", f"/Users/{scim_id}")
        else:
            patch = {"schemas": [PATCH_SCHEMA],
                     "Operations": [{"op": "replace", "path": "active", "value": False}]}
            r = self._req("PATCH", f"/Users/{scim_id}", data=json.dumps(patch))
        if r.status_code == 404:
            return  # schon weg
        if r.status_code not in (200, 204):
            raise self._fail(r, f"Remove {user_name}")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def setup_logging(log_file: str | None) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=8, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)


def main() -> int:
    ap = argparse.ArgumentParser(description="AD-Gruppe per SCIM an IdP synchronisieren (Delta)")
    ap.add_argument("group_dn", nargs="?", default=None,
                    help='z. B. "CN=SCIM-Sync,OU=Groups,DC=example,DC=local" '
                         '(optional, wenn GROUP_DN in der Umgebung/.env gesetzt ist)')
    ap.add_argument("--env-file", help="Datei mit KEY=VALUE (Berechtigungen einschraenken!)")
    ap.add_argument("--state-file", help="Pfad zur JSON-Datei (Default: ./state/<hash-des-DN>.json)")
    ap.add_argument("--log-file", default="logs/ad_scim_sync.log")
    ap.add_argument("--nested", action="store_true", help="Verschachtelte Gruppen aufloesen")
    ap.add_argument("--dry-run", action="store_true", help="Nur Delta anzeigen, nichts senden/speichern")
    ap.add_argument("--force", action="store_true", help="Sicherheitsgrenze fuer Loeschungen ignorieren")
    args = ap.parse_args()

    setup_logging(args.log_file)
    if args.env_file:
        load_env_file(args.env_file)

    # Kommandozeile hat Vorrang vor GROUP_DN aus Umgebung/.env
    group_dn = (args.group_dn or os.environ.get("GROUP_DN", "")).strip()
    if not group_dn:
        raise SystemExit("Gruppen-DN fehlt: als Argument uebergeben oder GROUP_DN setzen")
    args.group_dn = group_dn

    remove_mode = os.environ.get("SCIM_REMOVE_MODE", "deactivate").lower()
    if remove_mode not in ("deactivate", "delete"):
        raise SystemExit("SCIM_REMOVE_MODE muss 'deactivate' oder 'delete' sein")
    max_ratio = float(os.environ.get("MAX_REMOVE_RATIO", "0.3"))

    state_path = Path(args.state_file or
                      f"state/{hashlib.sha256(args.group_dn.lower().encode()).hexdigest()[:16]}.json")

    try:
        current = fetch_members(args.group_dn, args.nested)
        state = load_state(state_path, args.group_dn)
        old: dict[str, Any] = state["members"]
        added, changed, removed = compute_delta(old, current)
        log.info("Gruppe: %d Mitglieder | Delta: +%d ~%d -%d",
                 len(current), len(added), len(changed), len(removed))

        # Schutz gegen leere/defekte LDAP-Antworten
        if old and not args.force:
            if not current:
                log.error("Gruppe liefert 0 Mitglieder, State hat %d -> Abbruch (--force zum Ueberschreiben)", len(old))
                return 2
            if len(removed) >= 5 and len(removed) / len(old) > max_ratio:
                log.error("%d von %d Mitgliedern wuerden entfernt (> %.0f%%) -> Abbruch (--force)",
                          len(removed), len(old), max_ratio * 100)
                return 2

        if args.dry_run:
            for tag, ids in (("ADD", added), ("CHG", changed), ("DEL", removed)):
                for g in ids:
                    name = (current.get(g) or old[g]["attrs"])["userName"]
                    log.info("[dry-run] %s %s", tag, name)
            return 0

        if not (added or changed or removed):
            log.info("Keine Aenderungen")
            state["members"] = {g: {"attrs": current[g], "scim_id": old[g]["scim_id"]} for g in current}
            save_state(state_path, state)
            return 0

        client = ScimClient(need("SCIM_URL"), need("SCIM_SECRET"), remove_mode)
        new_members = {g: dict(v) for g, v in old.items()}
        errors = 0

        try:
            for g in added:
                try:
                    sid = client.create(g, current[g])
                    new_members[g] = {"attrs": current[g], "scim_id": sid}
                    log.info("ADD %s", current[g]["userName"])
                except ScimError as e:
                    errors += 1
                    log.error("%s", e)

            for g in changed:
                try:
                    try:
                        client.update(old[g]["scim_id"], g, current[g])
                        sid = old[g]["scim_id"]
                    except ScimNotFound:
                        sid = client.create(g, current[g])
                    new_members[g] = {"attrs": current[g], "scim_id": sid}
                    log.info("CHG %s", current[g]["userName"])
                except ScimError as e:
                    errors += 1
                    log.error("%s", e)

            for g in removed:
                try:
                    client.remove(old[g]["scim_id"], old[g]["attrs"]["userName"])
                    new_members.pop(g, None)
                    log.info("DEL(%s) %s", remove_mode, old[g]["attrs"]["userName"])
                except ScimError as e:
                    errors += 1
                    log.error("%s", e)
        finally:
            # auch bei Abbruch den bisherigen Fortschritt sichern
            state["members"] = new_members
            save_state(state_path, state)

        if errors:
            log.warning("%d Operation(en) fehlgeschlagen, werden beim naechsten Lauf erneut versucht", errors)
            return 1
        log.info("Fertig")
        return 0

    except SystemExit:
        raise
    except Exception:
        log.exception("Abbruch durch unerwarteten Fehler")
        return 2


if __name__ == "__main__":
    sys.exit(main())
