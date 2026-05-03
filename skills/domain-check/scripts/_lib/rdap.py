"""RDAP lookup with IANA bootstrap cache.

Platform-independent: uses only urllib.request from stdlib.
The cache lives in tempfile.gettempdir() (Linux: /tmp, macOS: /var/folders, Windows: %TEMP%).
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

RdapStatus = Literal["REGISTERED", "AVAILABLE", "ERROR"]

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
CACHE_TTL_SECONDS = 24 * 60 * 60
USER_AGENT = "domain-check-skill/1.0"


def _cache_path() -> Path:
    cache_dir = Path(tempfile.gettempdir()) / "domain-check-skill"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "rdap-bootstrap.json"


def _load_bootstrap() -> dict | None:
    p = _cache_path()
    if p.exists():
        age = time.time() - p.stat().st_mtime
        if age < CACHE_TTL_SECONDS:
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

    req = urllib.request.Request(BOOTSTRAP_URL, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        try:
            p.write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            pass
        return data
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None


def resolve_servers(domain: str) -> list[str]:
    """Return the RDAP base URLs for the domain's TLD."""
    bootstrap = _load_bootstrap()
    if not bootstrap:
        return []
    tld = domain.lower().rstrip(".").split(".")[-1]
    services = bootstrap.get("services", [])
    for entry in services:
        if len(entry) < 2:
            continue
        tlds, urls = entry[0], entry[1]
        if tld in [t.lower() for t in tlds]:
            return [url.rstrip("/") + "/" if not url.endswith("/") else url for url in urls]
    return []


@dataclass
class RdapResult:
    status: RdapStatus
    server: str | None
    expiration_date: str | None = None
    registrar: str | None = None
    nameservers: list[str] | None = None
    error: str | None = None
    raw: dict | None = None


def _fetch(url: str, timeout: float = 8.0) -> tuple[int, dict | None, str | None]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rdap+json, application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(body) if body else None, None
    except urllib.error.HTTPError as e:
        return e.code, None, str(e)
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError) as e:
        return 0, None, str(e)


def _parse(data: dict) -> tuple[str | None, str | None, list[str]]:
    """Returns (expiration_date, registrar, nameservers)."""
    expiration: str | None = None
    for event in data.get("events", []):
        if event.get("eventAction", "").lower() == "expiration":
            date = event.get("eventDate", "")
            expiration = date.split("T")[0] if "T" in date else date
            break

    registrar: str | None = None
    for entity in data.get("entities", []):
        roles = [r.lower() for r in entity.get("roles", [])]
        if "registrar" in roles:
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) >= 2:
                for field in vcard[1]:
                    if isinstance(field, list) and field and field[0] == "fn":
                        registrar = field[3] if len(field) >= 4 else None
                        break
            break

    nameservers = []
    for ns in data.get("nameservers", []):
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            nameservers.append(name.lower().rstrip("."))

    return expiration, registrar, nameservers


def lookup(domain: str, timeout: float = 8.0) -> RdapResult:
    servers = resolve_servers(domain)
    if not servers:
        return RdapResult("ERROR", None, error="No RDAP server known for TLD")

    last_error: str | None = None
    for base in servers:
        url = f"{base}domain/{domain}" if "domain/" not in base else f"{base}{domain}"
        status_code, data, err = _fetch(url, timeout=timeout)

        if status_code == 200 and data:
            if data.get("errorCode") == 404:
                return RdapResult("AVAILABLE", base)
            expiration, registrar, nameservers = _parse(data)
            return RdapResult(
                "REGISTERED", base,
                expiration_date=expiration,
                registrar=registrar,
                nameservers=nameservers,
                raw=data,
            )
        if status_code == 404:
            return RdapResult("AVAILABLE", base)
        if status_code == 429:
            time.sleep(0.5)
            status_code, data, err = _fetch(url, timeout=timeout)
            if status_code == 200 and data:
                expiration, registrar, nameservers = _parse(data)
                return RdapResult(
                    "REGISTERED", base,
                    expiration_date=expiration,
                    registrar=registrar,
                    nameservers=nameservers,
                    raw=data,
                )
            if status_code == 404:
                return RdapResult("AVAILABLE", base)
        last_error = err or f"HTTP {status_code}"

    return RdapResult("ERROR", None, error=last_error or "All RDAP endpoints failed")
