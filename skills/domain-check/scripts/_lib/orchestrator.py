"""Async orchestrator: runs all sources in parallel and assembles a user-friendly report."""
from __future__ import annotations

import asyncio
import socket
from typing import Any

from . import auth_dns, presence, rdap, tld_classifier, verdict, whois_client

# Strength mapping per source. Identical to the Android app (Kotlin EvidenceClassifier).
# CCTLD_DSGVO: RDAP no-object is unreliable (registries often don't expose RDAP at all).
# All other TLD classes: RDAP no-object is HARD_FREE (ICANN RDAP mandate).


def _idn_encode(domain: str) -> str:
    """münchen.de → xn--mnchen-3ya.de"""
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return domain.lower()


def _strength_rdap(status: str, tld_class: str) -> str:
    if status == "REGISTERED":
        return "HARD_TAKEN"
    if status == "AVAILABLE":
        return "INCONCLUSIVE" if tld_class == "CCTLD_DSGVO" else "HARD_FREE"
    return "ERROR"


def _strength_whois(status: str) -> str:
    return {
        "REGISTERED": "HARD_TAKEN",
        "RESERVED": "HARD_TAKEN",
        "AVAILABLE": "HARD_FREE",
        "INCONCLUSIVE": "INCONCLUSIVE",
    }.get(status, "ERROR")


def _strength_auth_dns(result: str) -> str:
    return {
        "TAKEN": "HARD_TAKEN",
        "FREE": "HARD_FREE",
        "INCONCLUSIVE": "INCONCLUSIVE",
        "ERROR": "ERROR",
    }.get(result, "ERROR")


def _strength_presence(signal: str) -> str:
    return {
        "TAKEN": "HARD_TAKEN",
        "FREE": "HARD_FREE",
        "INCONCLUSIVE": "INCONCLUSIVE",
        "ERROR": "ERROR",
    }.get(signal, "ERROR")


_VERDICT_MAP = {
    "TAKEN_CONFIRMED": "Taken",
    "TAKEN_LIKELY": "Taken",
    "AVAILABLE_CONFIRMED": "Available",
    "AVAILABLE_LIKELY": "Available",
    "RESERVED": "Reserved",
    "UNKNOWN": "Unclear",
}


def _buy_links(domain: str) -> dict[str, str]:
    """Returns direct purchase URLs at common registrars for an available domain."""
    from urllib.parse import quote
    enc = quote(domain, safe="")
    return {
        "spaceship": f"https://www.spaceship.com/domain-search/?query={enc}&tab=domains",
        "godaddy": f"https://www.godaddy.com/de/domainsearch/find?domainToCheck={enc}",
        "namecheap": f"https://www.namecheap.com/domains/registration/results/?domain={enc}",
        "porkbun": f"https://porkbun.com/checkout/search?q={enc}",
        "cloudflare": f"https://dash.cloudflare.com/?to=/:account/domains/register/{enc}",
    }

_DSGVO_NOTE = {
    "de": "DENIC confirms the registration but does not expose the expiry date publicly (GDPR).",
    "eu": "EURid confirms the registration but does not expose the expiry date publicly (GDPR).",
    "at": "Nic.at confirms the registration but does not expose the expiry date publicly.",
    "ch": "SWITCH does not publish expiry dates.",
    "li": "SWITCH does not publish expiry dates.",
    "es": "Red.es heavily restricts public WHOIS data.",
    "nl": "SIDN does not publish expiry dates (GDPR).",
}


async def check_domain(domain: str, timeout: float = 8.0) -> dict[str, Any]:
    """Single-domain check with user-friendly output."""
    domain = _idn_encode(domain.strip())
    tld_class = tld_classifier.classify(domain)
    tld = tld_classifier.extract_tld(domain)

    rdap_task = asyncio.to_thread(rdap.lookup, domain, timeout)
    whois_task = asyncio.to_thread(whois_client.lookup, domain, timeout)
    dns_task = asyncio.to_thread(presence.check_dns, domain, 3.0)
    web_task = asyncio.to_thread(presence.check_web, domain, 5.0)
    tls_task = asyncio.to_thread(presence.check_tls, domain, 443, 5.0)
    auth_task: asyncio.Future | None = None
    if auth_dns.supports(domain):
        auth_task = asyncio.to_thread(auth_dns.query, domain, 4.0)

    rdap_res, whois_res, dns_res, web_res, tls_res = await asyncio.gather(
        rdap_task, whois_task, dns_task, web_task, tls_task,
        return_exceptions=False,
    )
    auth_res = await auth_task if auth_task else None

    evidence: list[verdict.Evidence] = []
    evidence.append(verdict.Evidence(
        "RDAP",
        _strength_rdap(rdap_res.status, tld_class),
        rdap_res.error or f"RDAP {rdap_res.status}",
    ))
    evidence.append(verdict.Evidence(
        "WHOIS",
        _strength_whois(whois_res.status),
        whois_res.error or f"WHOIS {whois_res.status}",
    ))
    if auth_res:
        evidence.append(verdict.Evidence(
            "AUTH_DNS",
            _strength_auth_dns(auth_res.result),
            auth_res.error or f"Authoritative NS lookup: {auth_res.result}",
        ))
    evidence.append(verdict.Evidence(
        "DNS",
        _strength_presence(dns_res.signal),
        dns_res.error or (
            f"Address records: {', '.join(dns_res.addresses[:3])}"
            if dns_res.addresses else "No address records"
        ),
    ))
    evidence.append(verdict.Evidence(
        "WEB",
        _strength_presence(web_res.signal),
        web_res.error or f"HTTP/HTTPS responded ({web_res.https_status or web_res.http_status})",
    ))
    evidence.append(verdict.Evidence(
        "TLS",
        _strength_presence(tls_res.signal),
        tls_res.error or f"TLS cert from {tls_res.ip_address}",
    ))

    final = verdict.decide(tld_class, evidence)
    is_taken = final.status in ("TAKEN_CONFIRMED", "TAKEN_LIKELY")
    is_free = final.status in ("AVAILABLE_CONFIRMED", "AVAILABLE_LIKELY")

    report: dict[str, Any] = {
        "domain": domain,
        "verdict": _VERDICT_MAP[final.status],
        "confidence": final.confidence,
        "summary": final.summary,
    }

    if is_taken:
        # Expiry: prefer RDAP, then WHOIS
        expiry = rdap_res.expiration_date or whois_res.expiration_date
        report["expiration_date"] = expiry
        if not expiry and tld in _DSGVO_NOTE:
            report["expiration_note"] = _DSGVO_NOTE[tld]
        elif not expiry:
            report["expiration_note"] = "No public expiry date available."
        else:
            report["expiration_note"] = None

        report["registrar"] = rdap_res.registrar or whois_res.registrar
        report["nameservers"] = rdap_res.nameservers or (auth_res.ns_records if auth_res else None) or []
        report["ip_addresses"] = dns_res.addresses

        if tls_res.fingerprint_sha256:
            report["ssl"] = {
                "issuer": tls_res.issuer,
                "subject": tls_res.subject,
                "subject_alt_names": tls_res.subject_alt_names,
                "valid_from": tls_res.valid_from,
                "valid_to": tls_res.valid_to,
                "days_until_expiry": tls_res.days_until_expiry,
                "fingerprint_sha256": tls_res.fingerprint_sha256,
                "protocol": tls_res.protocol,
                "cipher": tls_res.cipher,
                "ip_address": tls_res.ip_address,
                "matches_hostname": tls_res.matches_hostname,
            }
        else:
            report["ssl"] = None
    else:
        # Available / Reserved / Unclear — compact
        report["expiration_date"] = None
        report["registrar"] = None
        report["nameservers"] = []
        report["ip_addresses"] = []
        report["ssl"] = None

    # Buy links: for "Available" direct registration; for "Taken" backorder/after-market lookup.
    report["buy_links"] = _buy_links(domain)

    report["evidence"] = [
        {"source": e.source, "strength": e.strength, "reason": e.reason}
        for e in final.evidence
    ]
    return report


async def check_bulk(domains: list[str], concurrency: int = 8, timeout: float = 8.0) -> list[dict[str, Any]]:
    """Bulk async with a global concurrency cap."""
    sem = asyncio.Semaphore(concurrency)

    async def _one(d: str) -> dict[str, Any]:
        async with sem:
            try:
                return await check_domain(d, timeout=timeout)
            except Exception as e:  # noqa: BLE001 — bulk runs must never crash
                return {
                    "domain": d,
                    "verdict": "Error",
                    "confidence": 0,
                    "summary": f"Check failed: {e}",
                    "evidence": [],
                }

    return await asyncio.gather(*(_one(d) for d in domains))


def check_ssl(hostname: str, port: int = 443) -> dict[str, Any]:
    """Standalone SSL certificate check."""
    result = presence.check_tls(hostname, port=port, timeout=5.0)
    if not result.fingerprint_sha256:
        return {
            "hostname": hostname,
            "port": port,
            "available": False,
            "error": result.error,
        }
    return {
        "hostname": hostname,
        "port": port,
        "available": True,
        "issuer": result.issuer,
        "subject": result.subject,
        "subject_alt_names": result.subject_alt_names,
        "valid_from": result.valid_from,
        "valid_to": result.valid_to,
        "days_until_expiry": result.days_until_expiry,
        "fingerprint_sha256": result.fingerprint_sha256,
        "protocol": result.protocol,
        "cipher": result.cipher,
        "ip_address": result.ip_address,
        "matches_hostname": result.matches_hostname,
    }


def resolve_host(target: str) -> dict[str, Any]:
    """URL/host → IPs + reverse DNS."""
    from urllib.parse import urlparse
    parsed = urlparse(target if "://" in target else f"http://{target}")
    hostname = (parsed.hostname or target).strip().lower()
    hostname = _idn_encode(hostname)

    ipv4: list[str] = []
    ipv6: list[str] = []
    try:
        for info in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
            family, _type, _proto, _canon, sockaddr = info
            ip = sockaddr[0]
            if family == socket.AF_INET and ip not in ipv4:
                ipv4.append(ip)
            elif family == socket.AF_INET6 and ip not in ipv6:
                ipv6.append(ip)
    except socket.gaierror as e:
        return {"hostname": hostname, "error": str(e), "ipv4": [], "ipv6": [], "reverse_dns": []}

    reverse: list[str] = []
    for ip in (ipv4 + ipv6)[:3]:
        try:
            host, _aliases, _ips = socket.gethostbyaddr(ip)
            if host and host not in reverse:
                reverse.append(host)
        except (socket.herror, OSError):
            pass

    return {
        "hostname": hostname,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "reverse_dns": reverse,
    }
