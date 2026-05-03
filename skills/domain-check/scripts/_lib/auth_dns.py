"""Native UDP DNS resolver for authoritative NS queries against registry NS servers.

Platform-independent (UDP sockets via stdlib `socket` work on Linux/macOS/Windows).
Wire format per RFC 1035, no external dependencies.

Use case: GDPR tiebreaker. For .de/.eu/.at/.ch the WHOIS response is often fully
redacted — a direct NS query against the registry NS servers gives a binary answer:
- NS records present  → registered (TAKEN)
- NXDOMAIN (rcode=3)  → available (FREE)
"""
from __future__ import annotations

import io
import secrets
import socket
import struct
from dataclasses import dataclass
from typing import Literal

NsResult = Literal["TAKEN", "FREE", "INCONCLUSIVE", "ERROR"]

AUTH_NS_BY_TLD: dict[str, list[str]] = {
    "de": ["a.nic.de", "f.nic.de", "l.de.net", "n.de.net", "s.de.net", "z.nic.de"],
    "eu": ["x.dns.eu", "y.dns.eu", "l.dns.eu"],
    "at": ["ns1.univie.ac.at", "r.ns.at", "d.ns.at"],
    "ch": ["a.nic.ch", "b.nic.ch", "f.nic.ch"],
    "li": ["a.nic.li", "b.nic.li"],
    "es": ["a.nic.es", "c.nic.es", "e.nic.es", "f.nic.es"],
    "nl": ["ns1.dns.nl", "ns2.dns.nl", "ns3.dns.nl"],
    "be": ["a.ns.dns.be", "b.ns.dns.be", "c.ns.dns.be"],
    "fr": ["d.nic.fr", "e.ext.nic.fr", "f.ext.nic.fr"],
    "it": ["a.dns.it", "dns.nic.it", "r.dns.it"],
    "pl": ["a-dns.pl", "b-dns.pl", "c-dns.pl"],
    "cz": ["a.ns.nic.cz", "b.ns.nic.cz", "c.ns.nic.cz"],
    "dk": ["a.nic.dk", "b.nic.dk", "s.nic.dk"],
    "se": ["a.ns.se", "b.ns.se", "c.ns.se"],
    "fi": ["a.fi", "b.fi", "c.fi"],
    "no": ["i.norid.no", "y.norid.no", "z.norid.no"],
    "pt": ["a.dns.pt", "b.dns.pt", "c.dns.pt"],
    "ie": ["a.ns.ie", "b.ns.ie", "c.ns.ie"],
    "ro": ["dns.rotld.ro", "secondary.rotld.ro"],
    "hu": ["a.hu", "b.hu", "c.hu"],
    "uk": ["dns1.nic.uk", "dns2.nic.uk", "dns3.nic.uk"],
    "co.uk": ["dns1.nic.uk", "dns2.nic.uk", "dns3.nic.uk"],
    "lu": ["i.dns.lu", "g.dns.lu", "k.dns.lu"],
    "com": ["a.gtld-servers.net", "b.gtld-servers.net", "m.gtld-servers.net"],
    "net": ["a.gtld-servers.net", "l.gtld-servers.net", "m.gtld-servers.net"],
    "org": ["a0.org.afilias-nst.info", "b0.org.afilias-nst.org"],
    "io": ["a0.nic.io", "b0.nic.io"],
    "ai": ["a.nic.ai", "b.nic.ai"],
}


@dataclass
class AuthDnsLookup:
    result: NsResult
    server: str | None
    rcode: int | None = None
    ns_records: list[str] | None = None
    error: str | None = None


def supports(domain: str) -> bool:
    return _extract_tld(domain) in AUTH_NS_BY_TLD


def _extract_tld(domain: str) -> str:
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return ""
    if len(parts) >= 3:
        two = ".".join(parts[-2:])
        if two in AUTH_NS_BY_TLD:
            return two
    return parts[-1]


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError(f"Label too long: {label}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def _build_query(name: str, transaction_id: int) -> bytes:
    # Header: id (2), flags (2, RD=0 = no recursion), qdcount=1, an/ns/ar=0
    header = struct.pack(">HHHHHH", transaction_id, 0x0000, 1, 0, 0, 0)
    qname = _encode_name(name)
    qtype_qclass = struct.pack(">HH", 2, 1)  # QTYPE=NS, QCLASS=IN
    return header + qname + qtype_qclass


def _skip_name(buf: io.BytesIO) -> None:
    while True:
        length_byte = buf.read(1)
        if not length_byte:
            return
        length = length_byte[0]
        if length == 0:
            return
        if (length & 0xC0) == 0xC0:
            buf.read(1)  # pointer is 2 bytes total
            return
        buf.read(length)


def _read_name(buf: io.BytesIO, full_data: bytes) -> str:
    labels: list[str] = []
    while True:
        length_byte = buf.read(1)
        if not length_byte:
            break
        length = length_byte[0]
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:
            offset = ((length & 0x3F) << 8) | buf.read(1)[0]
            sub_buf = io.BytesIO(full_data)
            sub_buf.seek(offset)
            labels.append(_read_name(sub_buf, full_data))
            return ".".join(labels)
        labels.append(buf.read(length).decode("ascii", errors="replace"))
    return ".".join(labels)


def _parse_response(data: bytes, expected_id: int) -> tuple[int, list[str]]:
    if len(data) < 12:
        return -1, []
    transaction_id, flags, qd, an, ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if transaction_id != expected_id:
        return -1, []
    rcode = flags & 0x0F

    buf = io.BytesIO(data[12:])
    # Question section
    for _ in range(qd):
        _skip_name(buf)
        buf.read(4)  # qtype + qclass

    ns_records: list[str] = []
    for _ in range(an + ns):
        _skip_name(buf)
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", buf.read(10))
        rdata = buf.read(rdlength)
        if rtype == 2:  # NS-record
            sub_buf = io.BytesIO(data)
            sub_buf.seek(len(data) - len(buf.getvalue()) + buf.tell() - rdlength)
            sub_buf.seek(data.find(rdata))
            try:
                name = _read_name(io.BytesIO(rdata), data)
                if name:
                    ns_records.append(name)
            except Exception:
                pass

    return rcode, ns_records


def query(domain: str, timeout: float = 4.0) -> AuthDnsLookup:
    tld = _extract_tld(domain)
    servers = AUTH_NS_BY_TLD.get(tld, [])
    if not servers:
        return AuthDnsLookup("INCONCLUSIVE", None, error="No authoritative NS configured")

    name = domain.lower().rstrip(".")
    last_error: str | None = None

    for server in servers:
        transaction_id = secrets.randbits(16)
        query_packet = _build_query(name, transaction_id)

        try:
            server_ip = socket.gethostbyname(server)
        except (socket.gaierror, OSError) as e:
            last_error = f"{server}: {e}"
            continue

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query_packet, (server_ip, 53))
                response, _ = sock.recvfrom(2048)
        except (socket.timeout, OSError) as e:
            last_error = f"{server}: {e}"
            continue

        rcode, ns_records = _parse_response(response, transaction_id)
        if rcode == 3:
            return AuthDnsLookup("FREE", server, rcode=rcode)
        if rcode == 0:
            if ns_records:
                return AuthDnsLookup("TAKEN", server, rcode=rcode, ns_records=ns_records)
            # rcode 0, no NS — zone cut does not confirm existence.
            return AuthDnsLookup("FREE", server, rcode=rcode)
        last_error = f"{server}: rcode={rcode}"

    return AuthDnsLookup("ERROR", None, error=last_error or "All NS queries failed")
