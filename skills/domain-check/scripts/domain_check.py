"""Platform-independent domain check tool (Linux/macOS/Windows).

Subcommands:
  check <domain>            — single-domain check (Available/Taken + SSL+IP+expiry when taken)
  bulk <d1> <d2> ...        — bulk async check, NDJSON output
  ssl <hostname>            — SSL certificate inspection
  resolve <url-or-host>     — URL/host → IPv4/IPv6 + reverse DNS

Output: JSON on stdout. Usage: python3 domain_check.py <subcommand> [args]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Import _lib as a sibling package — works on all three operating systems,
# regardless of the caller's working directory.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from _lib import naming, orchestrator  # noqa: E402


def _print_json(data, pretty: bool = True) -> None:
    if pretty:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(data, ensure_ascii=False))


def _format_table(reports: list[dict]) -> str:
    """Human-readable table for `bulk --format=table`."""
    rows = []
    rows.append(("DOMAIN", "VERDICT", "CONF", "EXPIRY", "REGISTRAR", "IP"))
    for r in reports:
        rows.append((
            r.get("domain", "?")[:40],
            r.get("verdict", "?"),
            f"{r.get('confidence', 0)}%",
            r.get("expiration_date") or "—",
            (r.get("registrar") or "—")[:25],
            (r.get("ip_addresses") or [""])[0] if r.get("ip_addresses") else "—",
        ))
    widths = [max(len(str(row[i])) for row in rows) for i in range(len(rows[0]))]
    lines = []
    for i, row in enumerate(rows):
        line = "  ".join(str(row[j]).ljust(widths[j]) for j in range(len(row)))
        lines.append(line)
        if i == 0:
            lines.append("  ".join("-" * w for w in widths))
    return "\n".join(lines)


def cmd_check(args: argparse.Namespace) -> int:
    report = asyncio.run(orchestrator.check_domain(args.domain, timeout=args.timeout))
    _print_json(report, pretty=not args.compact)
    return 0


def cmd_bulk(args: argparse.Namespace) -> int:
    domains: list[str] = list(args.domains or [])
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                d = line.strip()
                if d and not d.startswith("#"):
                    domains.append(d)
    if args.stdin:
        for line in sys.stdin:
            d = line.strip()
            if d and not d.startswith("#"):
                domains.append(d)
    if not domains:
        print("ERROR: no domains given (positional, --file, or --stdin)", file=sys.stderr)
        return 2

    reports = asyncio.run(orchestrator.check_bulk(domains, concurrency=args.concurrency, timeout=args.timeout))

    if args.format == "table":
        print(_format_table(reports))
    elif args.format == "json":
        _print_json(reports, pretty=True)
    else:  # ndjson (default)
        for r in reports:
            print(json.dumps(r, ensure_ascii=False))
    return 0


def cmd_ssl(args: argparse.Namespace) -> int:
    result = orchestrator.check_ssl(args.hostname, port=args.port)
    _print_json(result, pretty=not args.compact)
    return 0 if result.get("available") else 1


def cmd_resolve(args: argparse.Namespace) -> int:
    result = orchestrator.resolve_host(args.target)
    _print_json(result, pretty=not args.compact)
    return 0 if (result.get("ipv4") or result.get("ipv6")) else 1


def cmd_score(args: argparse.Namespace) -> int:
    """Auto-score a single name (without TLD)."""
    breakdown = naming.score_name(args.name)
    _print_json({
        "name": args.name,
        "score": breakdown.score,
        "components": breakdown.components,
        "notes": breakdown.notes,
    }, pretty=not args.compact)
    return 0


def cmd_suggest(args: argparse.Namespace) -> int:
    """Generate domain name candidates from a seed + use-case.
    If --check is set, also runs availability check on the top candidates.
    """
    candidates = naming.generate_candidates(args.seed, args.use_case, n=args.count)
    tld_rec = naming.recommend_tlds(args.use_case)
    primary_tlds = tld_rec["primary"] + tld_rec["secondary"]

    output: list[dict] = []
    for cand in candidates[:args.count]:
        entry = {
            "name": cand.name,
            "pattern": cand.pattern,
            "score": round(cand.score, 3),
            "pronunciation_hint": cand.pronunciation_hint,
            "suggested_tlds": primary_tlds[:3],
        }
        output.append(entry)

    result = {
        "seed": args.seed,
        "use_case": args.use_case,
        "tld_recommendation": tld_rec,
        "candidates": output,
    }

    # Optional: availability check on top N
    if args.check and output:
        top = output[: args.check_top]
        domains_to_check = []
        for entry in top:
            for tld in entry["suggested_tlds"][: args.tlds_per_name]:
                domains_to_check.append(f"{entry['name']}.{tld}")
        reports = asyncio.run(orchestrator.check_bulk(domains_to_check, concurrency=8))
        # Map back to candidates
        availability_map = {r["domain"]: r["verdict"] for r in reports}
        for entry in top:
            entry["availability"] = {
                f"{entry['name']}.{tld}": availability_map.get(f"{entry['name']}.{tld}", "Unknown")
                for tld in entry["suggested_tlds"][: args.tlds_per_name]
            }

    _print_json(result, pretty=not args.compact)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domain_check.py",
        description="Domain availability + SSL certificate + IP resolution (Available / Taken).",
    )
    parser.add_argument("--compact", action="store_true", help="JSON without indentation")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="Single-domain check")
    p_check.add_argument("domain")
    p_check.add_argument("--timeout", type=float, default=8.0)
    p_check.set_defaults(func=cmd_check)

    p_bulk = sub.add_parser("bulk", help="Bulk async check, NDJSON output")
    p_bulk.add_argument("domains", nargs="*")
    p_bulk.add_argument("--file", help="File with one domain per line")
    p_bulk.add_argument("--stdin", action="store_true", help="Read domains from stdin")
    p_bulk.add_argument("--concurrency", type=int, default=8)
    p_bulk.add_argument("--timeout", type=float, default=8.0)
    p_bulk.add_argument("--format", choices=("ndjson", "json", "table"), default="ndjson")
    p_bulk.set_defaults(func=cmd_bulk)

    p_ssl = sub.add_parser("ssl", help="SSL certificate inspection")
    p_ssl.add_argument("hostname")
    p_ssl.add_argument("--port", type=int, default=443)
    p_ssl.set_defaults(func=cmd_ssl)

    p_resolve = sub.add_parser("resolve", help="URL/host → IPv4/IPv6 + reverse DNS")
    p_resolve.add_argument("target", help="URL or hostname")
    p_resolve.set_defaults(func=cmd_resolve)

    p_score = sub.add_parser("score", help="Score a single name (without TLD) on naming heuristics")
    p_score.add_argument("name", help="bare name without TLD, e.g. 'lumenforge'")
    p_score.set_defaults(func=cmd_score)

    p_suggest = sub.add_parser("suggest", help="Generate domain candidates from a seed keyword + use-case")
    p_suggest.add_argument("seed", help="seed keyword, e.g. 'graph' or 'cloud'")
    p_suggest.add_argument(
        "--use-case",
        default="tech_startup",
        choices=list(naming.TLD_MATRIX.keys()),
        help="industry / project type (drives TLD recommendation)",
    )
    p_suggest.add_argument("--count", type=int, default=20, help="number of candidates to return")
    p_suggest.add_argument("--check", action="store_true", help="run availability check on top candidates")
    p_suggest.add_argument("--check-top", type=int, default=10, help="how many top candidates to check")
    p_suggest.add_argument("--tlds-per-name", type=int, default=2, help="how many TLDs per candidate to check")
    p_suggest.set_defaults(func=cmd_suggest)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
