"""TLD-aware decision tree for the final verdict.

Identical logic to the Android app (Kotlin VerdictEngine).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

VerdictStatus = Literal[
    "TAKEN_CONFIRMED",
    "AVAILABLE_CONFIRMED",
    "TAKEN_LIKELY",
    "AVAILABLE_LIKELY",
    "RESERVED",
    "UNKNOWN",
]

EvidenceStrength = Literal["HARD_TAKEN", "HARD_FREE", "SOFT_TAKEN", "INCONCLUSIVE", "ERROR"]


@dataclass
class Evidence:
    source: str  # "RDAP" | "WHOIS" | "AUTH_DNS" | "DNS" | "WEB" | "TLS"
    strength: EvidenceStrength
    reason: str


@dataclass
class FinalVerdict:
    status: VerdictStatus
    confidence: int
    summary: str
    primary_source: str | None = None
    evidence: list[Evidence] = field(default_factory=list)


AUTHORITY_SOURCES = {"RDAP", "WHOIS", "AUTH_DNS"}
PRESENCE_SOURCES = {"DNS", "WEB", "TLS"}


def decide(tld_class: str, evidence: list[Evidence]) -> FinalVerdict:
    """tld_class: 'GTLD_FULL' | 'CCTLD_DSGVO' | 'CCTLD_OPEN' | 'UNKNOWN'."""

    # 1) Reserved takes precedence
    reserved = next(
        (e for e in evidence if e.strength == "HARD_TAKEN" and any(
            kw in e.reason.lower() for kw in ("reserved", "restricted", "blocked")
        )),
        None,
    )
    if reserved:
        return FinalVerdict(
            "RESERVED", 95,
            "Reserved or restricted by registry",
            reserved.source, evidence,
        )

    # 2) If all relevant sources errored → Unknown
    relevant = [e for e in evidence if e.strength != "INCONCLUSIVE"]
    if relevant and all(e.strength == "ERROR" for e in relevant):
        return FinalVerdict(
            "UNKNOWN", 35,
            "All sources returned errors — retry recommended",
            None, evidence,
        )

    # 3) Authoritative HARD_TAKEN (RDAP/WHOIS) → TakenConfirmed
    auth_taken = next(
        (e for e in evidence
         if e.source in AUTHORITY_SOURCES and e.strength == "HARD_TAKEN"),
        None,
    )
    if auth_taken:
        return FinalVerdict(
            "TAKEN_CONFIRMED", 100,
            "Authoritative source confirms registration",
            auth_taken.source, evidence,
        )

    # 4) Authoritative DNS tiebreaker — decisive for GDPR TLDs
    auth_dns = next((e for e in evidence if e.source == "AUTH_DNS"), None)
    if auth_dns and tld_class == "CCTLD_DSGVO":
        if auth_dns.strength == "HARD_TAKEN":
            return FinalVerdict(
                "TAKEN_CONFIRMED", 100,
                "Registry NS-server confirms delegation",
                "AUTH_DNS", evidence,
            )
        if auth_dns.strength == "HARD_FREE":
            return FinalVerdict(
                "AVAILABLE_CONFIRMED", 100,
                "Registry NS-server returned NXDOMAIN",
                "AUTH_DNS", evidence,
            )

    # 5) Presence-only HARD_TAKEN → TakenLikely
    presence_taken = next(
        (e for e in evidence
         if e.source in PRESENCE_SOURCES and e.strength == "HARD_TAKEN"),
        None,
    )
    if presence_taken:
        return FinalVerdict(
            "TAKEN_LIKELY", 82,
            "Live DNS, web, or TLS evidence indicates the domain is in use",
            presence_taken.source, evidence,
        )

    # 6) HARD_FREE logic — TLD-aware
    rdap = next((e for e in evidence if e.source == "RDAP"), None)
    whois = next((e for e in evidence if e.source == "WHOIS"), None)
    dns = next((e for e in evidence if e.source == "DNS"), None)
    web = next((e for e in evidence if e.source == "WEB"), None)
    tls = next((e for e in evidence if e.source == "TLS"), None)

    presence_all_empty = all(
        e is None or e.strength == "HARD_FREE"
        for e in (dns, web, tls)
    ) and any(e is not None for e in (dns, web, tls))

    if tld_class == "GTLD_FULL":
        authorities_agree = (
            rdap is not None and rdap.strength == "HARD_FREE"
            and (whois is None or whois.strength in ("HARD_FREE", "INCONCLUSIVE"))
        )
        if authorities_agree and presence_all_empty:
            return FinalVerdict("AVAILABLE_CONFIRMED", 100,
                                "RDAP no-object, no DNS/web/TLS presence", "RDAP", evidence)
        if authorities_agree:
            return FinalVerdict("AVAILABLE_LIKELY", 90,
                                "RDAP no-object; presence partially inconclusive", "RDAP", evidence)
        if whois and whois.strength == "HARD_FREE" and presence_all_empty:
            return FinalVerdict("AVAILABLE_CONFIRMED", 100,
                                "WHOIS confirms not registered, no presence", "WHOIS", evidence)

    elif tld_class == "CCTLD_DSGVO":
        whois_free = whois is not None and whois.strength == "HARD_FREE"
        if whois_free and presence_all_empty:
            return FinalVerdict("AVAILABLE_CONFIRMED", 100,
                                "WHOIS confirms not registered, no presence", "WHOIS", evidence)
        if whois_free:
            return FinalVerdict("AVAILABLE_LIKELY", 90,
                                "WHOIS not registered; presence partially inconclusive",
                                "WHOIS", evidence)
        # If WHOIS is unclear (GDPR redaction) but presence is clearly empty
        if presence_all_empty and (whois is None or whois.strength != "HARD_TAKEN"):
            return FinalVerdict("AVAILABLE_LIKELY", 85,
                                "No DNS/web/TLS presence; WHOIS inconclusive (DSGVO)",
                                "DNS", evidence)

    else:  # CCTLD_OPEN, UNKNOWN
        any_authority_free = any(
            e is not None and e.strength == "HARD_FREE"
            for e in (rdap, whois)
        )
        if any_authority_free and presence_all_empty:
            return FinalVerdict("AVAILABLE_CONFIRMED", 100,
                                "Authority says not registered, no presence", None, evidence)
        if any_authority_free:
            return FinalVerdict("AVAILABLE_LIKELY", 90,
                                "Authority says not registered; presence partially inconclusive",
                                None, evidence)

    # 7) Soft-Taken
    soft = next((e for e in evidence if e.strength == "SOFT_TAKEN"), None)
    if soft:
        return FinalVerdict("TAKEN_LIKELY", 75,
                            "Soft signal indicates registration", soft.source, evidence)

    return FinalVerdict("UNKNOWN", 35,
                        "No reliable availability signal", None, evidence)
