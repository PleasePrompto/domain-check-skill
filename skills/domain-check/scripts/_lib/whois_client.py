"""WHOIS client with a TLD pattern library for 30+ TLDs.

Live-verified WHOIS patterns for DACH/EU ccTLDs and gTLDs.
Classification order: TLD-specific → generic → null.
"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from typing import Literal

WhoisStatus = Literal["REGISTERED", "AVAILABLE", "RESERVED", "INCONCLUSIVE"]

# TLD → WHOIS server map (most common TLDs hardcoded; rest via IANA lookup).
TLD_WHOIS_SERVERS: dict[str, str] = {
    "de": "whois.denic.de", "eu": "whois.eu", "at": "whois.nic.at",
    "ch": "whois.nic.ch", "li": "whois.nic.li", "nl": "whois.domain-registry.nl",
    "be": "whois.dns.be", "fr": "whois.nic.fr", "it": "whois.nic.it",
    "es": "whois.nic.es", "pl": "whois.dns.pl", "cz": "whois.nic.cz",
    "dk": "whois.dk-hostmaster.dk", "se": "whois.iis.se", "fi": "whois.fi",
    "no": "whois.norid.no", "pt": "whois.dns.pt", "ie": "whois.weare.ie",
    "ro": "whois.rotld.ro", "hu": "whois.nic.hu", "uk": "whois.nic.uk",
    "co.uk": "whois.nic.uk", "lu": "whois.dns.lu",
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.publicinterestregistry.org", "info": "whois.afilias.net",
    "io": "whois.nic.io", "ai": "whois.nic.ai", "xyz": "whois.nic.xyz",
    "app": "whois.nic.google", "dev": "whois.nic.google",
}

FLAGS = re.IGNORECASE | re.MULTILINE


@dataclass
class TldPatterns:
    free: re.Pattern | None
    taken: re.Pattern | None
    expiry: re.Pattern | None = None


# Live-verified patterns for 30+ TLDs.
TLD_PATTERNS: dict[str, TldPatterns] = {
    # DACH/EU ccTLDs (GDPR-redacted)
    "de": TldPatterns(
        re.compile(r"^\s*Status:\s*free\b", FLAGS),
        re.compile(r"^\s*Status:\s*(connect|invalid|failed)\b", FLAGS),
    ),
    "eu": TldPatterns(
        re.compile(r"Visit www\.eurid\.eu.*?registration records", FLAGS | re.DOTALL),
        re.compile(r"^Domain:\s*\S+\s*$", FLAGS),
    ),
    "at": TldPatterns(
        re.compile(r"\A\s*%\s*Copyright", FLAGS | re.DOTALL),
        re.compile(r"^domain:\s+\S+", FLAGS),
    ),
    "ch": TldPatterns(
        re.compile(r"Requests of this client are not permitted", FLAGS),
        re.compile(r"^domain:\s+\S+", FLAGS),
    ),
    "li": TldPatterns(
        re.compile(r"Requests of this client are not permitted", FLAGS),
        re.compile(r"^domain:\s+\S+", FLAGS),
    ),
    "nl": TldPatterns(
        re.compile(r"\bis\s+free\b", FLAGS),
        re.compile(r"^Status:\s*(active|quarantine)\b", FLAGS),
    ),
    "be": TldPatterns(
        re.compile(r"Status:\s*(AVAILABLE|FREE)", FLAGS),
        re.compile(r"^Status:\s*NOT\s*AVAILABLE", FLAGS),
    ),
    "fr": TldPatterns(
        re.compile(r"%%\s*NOT\s*FOUND", FLAGS),
        re.compile(r"^status:\s*ACTIVE", FLAGS),
        re.compile(r"^Expiry\s*Date:\s*(\S+)", FLAGS),
    ),
    "it": TldPatterns(
        re.compile(r"^Status:\s*AVAILABLE\b", FLAGS),
        re.compile(r"^Status:\s*(ok|active|inactive|pendingDelete|pendingTransfer|pendingUpdate)\b", FLAGS),
        re.compile(r"^Expire\s*Date:\s*(\S+)", FLAGS),
    ),
    "es": TldPatterns(
        re.compile(r"Conditions of use for the whois service", FLAGS),
        re.compile(r"^Domain Name:\s*\S+", FLAGS),
    ),
    "pl": TldPatterns(
        re.compile(r"No information available about domain name", FLAGS),
        re.compile(r"^DOMAIN NAME:\s+\S+", FLAGS),
    ),
    "cz": TldPatterns(
        re.compile(r"\bnot found\b|^%ERROR:101", FLAGS),
        re.compile(r"^domain:\s+\S+", FLAGS),
        re.compile(r"^expire:\s*(\S+)", FLAGS),
    ),
    "dk": TldPatterns(
        re.compile(r"\bNo entries found\b", FLAGS),
        re.compile(r"^Domain:\s+\S+", FLAGS),
    ),
    "se": TldPatterns(
        re.compile(r"not found.|domain.*not found", FLAGS),
        re.compile(r"^state:\s*active", FLAGS),
        re.compile(r"^expires:\s*(\S+)", FLAGS),
    ),
    "fi": TldPatterns(
        re.compile(r"Domain not found", FLAGS),
        re.compile(r"^status\.+:\s*Registered", FLAGS),
        re.compile(r"^expires\.+:\s*(\S+\s+\S+)", FLAGS),
    ),
    "no": TldPatterns(
        re.compile(r"\bno match\b", FLAGS),
        re.compile(r"^Domain Name\.+:\s+\S+", FLAGS),
    ),
    "pt": TldPatterns(
        re.compile(r"-\s*No\s*Match", FLAGS),
        re.compile(r"^Domain Status:\s*Registered", FLAGS),
        re.compile(r"^Expiration Date:\s*(\S+)", FLAGS),
    ),
    "ie": TldPatterns(
        re.compile(r"^Not found:", FLAGS),
        re.compile(r"^Domain Name:\s+\S+", FLAGS),
        re.compile(r"^Registry Expiry Date:\s*(\S+)", FLAGS),
    ),
    "ro": TldPatterns(
        re.compile(r"\bno entries found\b", FLAGS),
        re.compile(r"^\s*Domain Name:\s+\S+", FLAGS),
    ),
    "hu": TldPatterns(
        re.compile(r"(?:Nincs\s*talalat|No\s*match)", FLAGS),
        re.compile(r"^domain:\s+\S+", FLAGS),
    ),
    "uk": TldPatterns(
        re.compile(r"No match for", FLAGS),
        re.compile(r"^\s*Domain name:", FLAGS),
        re.compile(r"^\s*Expiry date:\s*(\S+)", FLAGS),
    ),
    "co.uk": TldPatterns(
        re.compile(r"No match for", FLAGS),
        re.compile(r"^\s*Domain name:", FLAGS),
        re.compile(r"^\s*Expiry date:\s*(\S+)", FLAGS),
    ),
    "lu": TldPatterns(
        re.compile(r"\bNo entries found\b|domainname:\s*$", FLAGS),
        re.compile(r"^domaintype:\s*ACTIVE", FLAGS),
    ),
    # gTLDs
    "com": TldPatterns(
        re.compile(r"No match for", FLAGS),
        re.compile(r"^\s*Domain Name:\s+\S+", FLAGS),
        re.compile(r"^\s*Registry Expiry Date:\s*(\S+)", FLAGS),
    ),
    "net": TldPatterns(
        re.compile(r"No match for", FLAGS),
        re.compile(r"^\s*Domain Name:", FLAGS),
        re.compile(r"^\s*Registry Expiry Date:\s*(\S+)", FLAGS),
    ),
    "org": TldPatterns(
        re.compile(r"NOT\s+FOUND", FLAGS),
        re.compile(r"^Domain Name:", FLAGS),
        re.compile(r"^Registry Expiry Date:\s*(\S+)", FLAGS),
    ),
    "io": TldPatterns(
        re.compile(r"is available for purchase", FLAGS),
        re.compile(r"^Domain Name:", FLAGS),
        re.compile(r"^Registry Expiry Date:\s*(\S+)", FLAGS),
    ),
    "ai": TldPatterns(
        re.compile(r"If you would like to register", FLAGS),
        re.compile(r"^Domain Name:", FLAGS),
        re.compile(r"^Registry Expiry Date:\s*(\S+)", FLAGS),
    ),
    "xyz": TldPatterns(
        re.compile(r"DOMAIN NOT FOUND", FLAGS),
        re.compile(r"^Domain Name:", FLAGS),
        re.compile(r"^Registry Expiry Date:\s*(\S+)", FLAGS),
    ),
    "info": TldPatterns(
        re.compile(r"NOT FOUND", FLAGS),
        re.compile(r"^Domain Name:", FLAGS),
        re.compile(r"^Registry Expiry Date:\s*(\S+)", FLAGS),
    ),
    "app": TldPatterns(
        re.compile(r"domain not found", FLAGS),
        re.compile(r"^Domain Name:", FLAGS),
        re.compile(r"^Registry Expiry Date:\s*(\S+)", FLAGS),
    ),
    "dev": TldPatterns(
        re.compile(r"domain not found", FLAGS),
        re.compile(r"^Domain Name:", FLAGS),
        re.compile(r"^Registry Expiry Date:\s*(\S+)", FLAGS),
    ),
}

# Generic fallbacks for unknown TLDs.
GENERIC_FREE = re.compile(
    r"\b(no match|not found|no entries found|no data found|status:\s*available|"
    r"domain not found|is free|no object found|not registered|object does not exist|"
    r"available for registration)\b",
    FLAGS,
)
GENERIC_TAKEN = re.compile(r"^\s*(domain name|domain|domainname):\s*\S+", FLAGS)

RESERVED_PATTERN = re.compile(
    r"(reserved name|reserved domain|domain is reserved|reserved by the registry|"
    r"blocked name|domain is blocked|cannot be registered|restricted registration|"
    r"premium name)",
    FLAGS,
)

RATE_LIMIT_PATTERN = re.compile(
    r"\b(too many requests|quota exceeded|rate[\s_-]?limit|please wait)\b",
    re.IGNORECASE,
)

REGISTRAR_BY_TLD = {
    "de": "DENIC eG", "eu": "EURid", "at": "Nic.at", "ch": "SWITCH",
    "li": "SWITCH", "nl": "SIDN", "fr": "AFNIC", "it": "Nic.it",
    "es": "Red.es", "pl": "NASK", "cz": "CZ.NIC", "uk": "Nominet",
    "se": "IIS", "fi": "Traficom", "no": "Norid", "be": "DNS.be",
    "dk": "DK Hostmaster", "pt": "DNS.PT", "ie": "IEDR", "ro": "ROTLD",
    "hu": "Nic.hu", "lu": "RESTENA",
}


@dataclass
class WhoisResult:
    status: WhoisStatus
    raw: str | None
    server: str | None
    registrar: str | None = None
    expiration_date: str | None = None
    rate_limited: bool = False
    error: str | None = None


def _patterns_for(domain: str) -> tuple[str, TldPatterns | None]:
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) >= 3:
        two = ".".join(parts[-2:])
        if two in TLD_PATTERNS:
            return two, TLD_PATTERNS[two]
    tld = parts[-1] if parts else ""
    return tld, TLD_PATTERNS.get(tld)


_IANA_CACHE: dict[str, str] = {}
_IANA_CACHE_PATH = None  # lazy init in _server_for


def _iana_cache_path():
    global _IANA_CACHE_PATH
    if _IANA_CACHE_PATH is not None:
        return _IANA_CACHE_PATH
    import tempfile
    from pathlib import Path
    cache_dir = Path(tempfile.gettempdir()) / "domain-check-skill"
    cache_dir.mkdir(parents=True, exist_ok=True)
    _IANA_CACHE_PATH = cache_dir / "iana-whois-servers.json"
    return _IANA_CACHE_PATH


def _load_iana_cache() -> dict[str, str]:
    global _IANA_CACHE
    if _IANA_CACHE:
        return _IANA_CACHE
    import json as _json
    p = _iana_cache_path()
    if p.exists():
        try:
            _IANA_CACHE = _json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _IANA_CACHE = {}
    return _IANA_CACHE


def _save_iana_cache() -> None:
    import json as _json
    try:
        _iana_cache_path().write_text(_json.dumps(_IANA_CACHE), encoding="utf-8")
    except OSError:
        pass


_IANA_WHOIS_LINE = re.compile(r"^\s*whois:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


def _discover_via_iana(tld: str, timeout: float = 6.0) -> str | None:
    """Live discovery: TCP/43 → whois.iana.org → parse the 'whois:' line."""
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=timeout) as sock:
            sock.sendall(f"{tld}\r\n".encode("utf-8"))
            chunks: list[bytes] = []
            sock.settimeout(timeout)
            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
        text = b"".join(chunks).decode("utf-8", errors="replace")
    except (socket.error, OSError):
        return None

    m = _IANA_WHOIS_LINE.search(text)
    if not m:
        return None
    server = m.group(1).strip().lower()
    if not server or " " in server or "." not in server:
        return None
    return server


def _server_for(domain: str) -> str | None:
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) >= 3:
        two = ".".join(parts[-2:])
        if two in TLD_WHOIS_SERVERS:
            return TLD_WHOIS_SERVERS[two]
    tld = parts[-1] if parts else ""
    if tld in TLD_WHOIS_SERVERS:
        return TLD_WHOIS_SERVERS[tld]

    # Tier 2 lookup: persistent cache (TTL implicit via filesystem mtime; flat JSON here).
    cache = _load_iana_cache()
    if tld in cache:
        return cache[tld]

    # Tier 3 discovery: query whois.iana.org live and populate the cache.
    discovered = _discover_via_iana(tld)
    if discovered:
        cache[tld] = discovered
        _save_iana_cache()
        return discovered
    return None


def _query_socket(domain: str, server: str, timeout: float = 8.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall(f"{domain}\r\n".encode("utf-8"))
        chunks: list[bytes] = []
        sock.settimeout(timeout)
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace")


REFERRAL_PATTERNS = [
    re.compile(r"^Registrar WHOIS Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^ReferralServer:\s*whois://(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^refer:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^whois server:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
]


def _extract_referral(text: str, current_server: str) -> str | None:
    for pattern in REFERRAL_PATTERNS:
        m = pattern.search(text)
        if not m:
            continue
        host = m.group(1).strip().lower()
        host = re.sub(r"^whois://", "", host)
        host = host.split("/")[0].split("?")[0].split(":")[0]
        if not host or host == current_server or host == "whois.iana.org":
            continue
        return host
    return None


def lookup(domain: str, timeout: float = 8.0) -> WhoisResult:
    """Run a WHOIS lookup with referral following and TLD pattern matching."""
    server = _server_for(domain)
    if not server:
        return WhoisResult("INCONCLUSIVE", None, None, error="No WHOIS server known for TLD")

    try:
        raw = _query_socket(domain, server, timeout=timeout)
    except (socket.error, OSError) as e:
        return WhoisResult("INCONCLUSIVE", None, server, error=f"Connect failed: {e}")

    if RATE_LIMIT_PATTERN.search(raw):
        return WhoisResult("INCONCLUSIVE", raw, server, rate_limited=True)

    referral = _extract_referral(raw, server)
    if referral:
        try:
            raw2 = _query_socket(domain, referral, timeout=timeout)
            if not RATE_LIMIT_PATTERN.search(raw2) and len(raw2) > 50:
                raw = raw2
                server = referral
        except (socket.error, OSError):
            pass  # Referral failed, keep initial response

    return _classify(raw, server, domain)


def _classify(raw: str, server: str, domain: str) -> WhoisResult:
    tld, patterns = _patterns_for(domain)

    if RESERVED_PATTERN.search(raw):
        return WhoisResult("RESERVED", raw, server)

    if patterns:
        if patterns.taken and patterns.taken.search(raw):
            expiry = None
            if patterns.expiry:
                m = patterns.expiry.search(raw)
                if m:
                    expiry = m.group(1)
            return WhoisResult(
                "REGISTERED", raw, server,
                registrar=REGISTRAR_BY_TLD.get(tld),
                expiration_date=expiry,
            )
        if patterns.free and patterns.free.search(raw):
            return WhoisResult("AVAILABLE", raw, server)

    # Generic fallback
    if GENERIC_FREE.search(raw):
        return WhoisResult("AVAILABLE", raw, server)
    if GENERIC_TAKEN.search(raw):
        return WhoisResult("REGISTERED", raw, server, registrar=REGISTRAR_BY_TLD.get(tld))

    # Heuristic available fallback: if the response is only disclaimers/headers (no
    # domain/registrar fields), the domain is most likely not registered.
    payload_lines = [
        ln.strip() for ln in raw.splitlines()
        if ln.strip() and not ln.lstrip().startswith(("%", "#"))
    ]
    registration_markers = (
        "domain name:", "domain:", "domainname:", "registrar:", "registrant:",
        "name server", "nserver", "created:", "creation date:", "registered:",
        "sponsoring registrar:",
    )
    has_registration_fields = any(
        ln.lower().startswith(registration_markers) for ln in payload_lines
    )
    if not has_registration_fields:
        return WhoisResult("AVAILABLE", raw, server)

    return WhoisResult("INCONCLUSIVE", raw, server)


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) < 2:
        print("Usage: whois_client.py <domain>", file=sys.stderr)
        sys.exit(1)
    result = lookup(sys.argv[1])
    print(json.dumps({
        "status": result.status,
        "server": result.server,
        "registrar": result.registrar,
        "expiration_date": result.expiration_date,
        "rate_limited": result.rate_limited,
        "error": result.error,
        "raw_preview": (result.raw or "")[:500],
    }, indent=2, ensure_ascii=False))
