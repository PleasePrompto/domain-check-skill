"""TLD cluster classification for the TLD-aware decision tree."""
from __future__ import annotations

GTLD_FULL = {
    "com", "net", "org", "io", "ai", "app", "dev", "co", "xyz", "info",
    "biz", "me", "sh", "tv", "us", "ws", "fm", "gg", "live", "tech",
    "store", "online", "site", "shop", "blog", "cloud", "page", "fyi",
    "art", "best", "one", "new", "chat", "llc", "inc", "cc", "ac",
}

CCTLD_DSGVO = {
    "at", "be", "bg", "ch", "cy", "cz", "de", "dk", "ee", "es",
    "eu", "fi", "fr", "gr", "hr", "hu", "ie", "it", "li", "lt",
    "lu", "lv", "mt", "nl", "no", "pl", "pt", "ro", "se", "si",
    "sk", "uk",
}

CCTLD_OPEN = {
    "ca", "jp", "kr", "au", "nz", "br", "mx", "in", "cn", "hk",
    "sg", "tw", "za", "tr", "ru",
}


def classify(domain: str) -> str:
    """Returns: 'GTLD_FULL' | 'CCTLD_DSGVO' | 'CCTLD_OPEN' | 'UNKNOWN'."""
    tld = extract_tld(domain)
    if tld in GTLD_FULL:
        return "GTLD_FULL"
    if tld in CCTLD_DSGVO:
        return "CCTLD_DSGVO"
    if tld in CCTLD_OPEN:
        return "CCTLD_OPEN"
    return "UNKNOWN"


def extract_tld(domain: str) -> str:
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return ""
    # Try multi-label TLD (e.g. co.uk) first
    if len(parts) >= 3:
        two = ".".join(parts[-2:])
        if two in CCTLD_DSGVO or two in CCTLD_OPEN or two in GTLD_FULL:
            return two
    return parts[-1]
