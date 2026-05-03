"""Presence checks: DNS A/AAAA, HTTP/HTTPS reachability, TLS cert.

Platform-independent (stdlib only).
"""
from __future__ import annotations

import hashlib
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

PresenceSignal = Literal["TAKEN", "FREE", "INCONCLUSIVE", "ERROR"]


@dataclass
class DnsLookup:
    signal: PresenceSignal
    addresses: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class WebLookup:
    signal: PresenceSignal
    https_status: int | None = None
    http_status: int | None = None
    final_url: str | None = None
    error: str | None = None


@dataclass
class TlsLookup:
    signal: PresenceSignal
    issuer: str | None = None
    subject: str | None = None
    subject_alt_names: list[str] = field(default_factory=list)
    valid_from: str | None = None
    valid_to: str | None = None
    days_until_expiry: int | None = None
    fingerprint_sha256: str | None = None
    protocol: str | None = None
    cipher: str | None = None
    ip_address: str | None = None
    matches_hostname: bool | None = None
    error: str | None = None


def check_dns(domain: str, timeout: float = 3.0) -> DnsLookup:
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        addrs = sorted({info[4][0] for info in infos})
        if addrs:
            return DnsLookup("TAKEN", addresses=addrs)
        return DnsLookup("FREE")
    except socket.gaierror as e:
        msg = str(e).lower()
        if "name or service not known" in msg or "nodename nor servname" in msg or "no address" in msg:
            return DnsLookup("FREE", error=str(e))
        return DnsLookup("ERROR", error=str(e))
    except (OSError, socket.timeout) as e:
        return DnsLookup("ERROR", error=str(e))
    finally:
        socket.setdefaulttimeout(None)


def _http_status(url: str, timeout: float) -> tuple[int | None, str | None, str | None]:
    """Returns (status_code, final_url, error)."""
    req = urllib.request.Request(url, headers={"User-Agent": "domain-check-skill/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.geturl(), None
    except urllib.error.HTTPError as e:
        return e.code, url, None
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        return None, None, str(e)


def check_web(domain: str, timeout: float = 5.0) -> WebLookup:
    https_status, https_url, https_err = _http_status(f"https://{domain}/", timeout=timeout)
    if https_status is not None and 200 <= https_status < 400:
        return WebLookup("TAKEN", https_status=https_status, final_url=https_url)
    if https_status is not None and 500 <= https_status < 600:
        return WebLookup("ERROR", https_status=https_status, error=f"HTTPS {https_status}")
    if https_status is not None and 400 <= https_status < 500 and https_status != 404:
        return WebLookup("INCONCLUSIVE", https_status=https_status)

    http_status, http_url, http_err = _http_status(f"http://{domain}/", timeout=timeout)
    if http_status is not None and 200 <= http_status < 400:
        return WebLookup("TAKEN", https_status=https_status, http_status=http_status, final_url=http_url)
    if http_status is not None and 400 <= http_status < 500 and http_status != 404:
        return WebLookup("INCONCLUSIVE", http_status=http_status)

    error = https_err or http_err or "No HTTP/HTTPS response"
    return WebLookup("FREE", https_status=https_status, http_status=http_status, error=error)


def _parse_pem_cert(pem: str) -> dict:
    """Manual PEM parser used as a fallback when ssl.getpeercert() is empty.
    Uses _ssl._test_decode_cert when available; otherwise the openssl CLI as a last resort.
    """
    # Attempt 1: ssl._ssl._test_decode_cert via temp file (cross-platform stdlib)
    import tempfile
    import os
    try:
        # _ssl._test_decode_cert is private API but stable since Python 3.4
        from _ssl import _test_decode_cert  # type: ignore[import-not-found]
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(pem)
            return _test_decode_cert(path)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    except (ImportError, AttributeError, ssl.SSLError, OSError):
        return {}


def _matches_hostname(domain: str, subject_cn: str | None, sans: list[str]) -> bool:
    target = domain.lower().rstrip(".")
    candidates = [s.lower().rstrip(".") for s in sans]
    if subject_cn:
        candidates.append(subject_cn.lower().rstrip("."))
    for cand in candidates:
        if not cand:
            continue
        if cand == target:
            return True
        if cand.startswith("*."):
            suffix = cand[1:]
            if target.endswith(suffix) and target.removesuffix(suffix).count(".") == 0:
                return True
    return False


def check_tls(domain: str, port: int = 443, timeout: float = 5.0) -> TlsLookup:
    """Fetch the TLS certificate. Two-stage strategy:
    1. Verified context (returns full cert_dict with issuer/subject/SAN).
    2. If validation fails: unverified fallback + manual DER parser.
    """
    ip_address: str | None = None
    der_cert: bytes | None = None
    cert_dict: dict | None = None
    protocol: str | None = None
    cipher_info = None
    last_error: str | None = None

    # Stage 1: strict / verified (returns a complete dict)
    try:
        verified_ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            ip_address = sock.getpeername()[0]
            with verified_ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
                cert_dict = tls_sock.getpeercert()
                protocol = tls_sock.version()
                cipher_info = tls_sock.cipher()
    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as e:
        last_error = str(e)

    # Stage 2: lenient (extract cert even on hostname mismatch / self-signed)
    if not der_cert:
        try:
            unverified_ctx = ssl._create_unverified_context()  # type: ignore[attr-defined]
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                ip_address = sock.getpeername()[0]
                with unverified_ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    der_cert = tls_sock.getpeercert(binary_form=True)
                    protocol = tls_sock.version()
                    cipher_info = tls_sock.cipher()
            # cert_dict is empty in unverified mode → parse manually from PEM via _parse_pem_cert
            if der_cert:
                pem = ssl.DER_cert_to_PEM_cert(der_cert)
                cert_dict = _parse_pem_cert(pem)
        except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as e:
            return TlsLookup("FREE", error=last_error or str(e))

    if not der_cert:
        return TlsLookup("FREE", error="No certificate returned", ip_address=ip_address)

    # Without verification we often don't get a dict — fall back to parsing via DER.
    issuer = subject_cn = valid_from = valid_to = None
    sans: list[str] = []
    if cert_dict:
        issuer = ", ".join(f"{k[0][0]}={k[0][1]}" for k in cert_dict.get("issuer", ()))
        subject_parts = cert_dict.get("subject", ())
        for part in subject_parts:
            if part and part[0][0] == "commonName":
                subject_cn = part[0][1]
                break
        valid_from = cert_dict.get("notBefore")
        valid_to = cert_dict.get("notAfter")
        for typ, val in cert_dict.get("subjectAltName", ()):
            if typ == "DNS":
                sans.append(val)

    days_until = None
    if valid_to:
        try:
            dt = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z")
            days_until = (dt.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    fingerprint = hashlib.sha256(der_cert).hexdigest()
    matches = _matches_hostname(domain, subject_cn, sans)

    cipher_name = cipher_info[0] if cipher_info else None
    signal: PresenceSignal = "TAKEN" if matches else "INCONCLUSIVE"

    return TlsLookup(
        signal=signal,
        issuer=issuer,
        subject=subject_cn,
        subject_alt_names=sans,
        valid_from=valid_from,
        valid_to=valid_to,
        days_until_expiry=days_until,
        fingerprint_sha256=fingerprint,
        protocol=protocol,
        cipher=cipher_name,
        ip_address=ip_address,
        matches_hostname=matches,
    )
