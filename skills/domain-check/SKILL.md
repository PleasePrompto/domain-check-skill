---
name: domain-check
description: 'Check domain availability (Available/Taken) for any TLD with confidence scoring, SSL certificate inspection, and IP resolution. Uses 5+ sources in parallel — RDAP, WHOIS (TLD-specific patterns for 30+ ccTLDs/gTLDs, IANA fallback for unknown TLDs), authoritative DNS NS lookup as GDPR tiebreaker for .de/.eu/.at/.ch/.es, DNS A/AAAA, HTTP reachability, and TLS certificate validation. Returns a clear binary verdict; when Taken, inline includes registrar, expiration date (or note if registry redacts under GDPR), nameservers, server IPs, and full SSL cert details. Single-domain or bulk-async (30 domains in ~10s). Stateless, stdlib-only, runs identically on Linux, macOS, and Windows. Use when the user asks if a domain is free/taken/available/registered, wants WHOIS or RDAP info, SSL certificate details, or to resolve a URL/domain to its server IPs. Triggers — "is X.com free", "check this domain", "bulk domain check", "SSL cert of X", "what IP does X resolve to", "domain availability", "ist X.de frei", "domain prüfen", "Belegt oder frei".'
---

# domain-check

Platform-independent domain checker. Answers the binary question **Available / Taken** with high confidence (100% when all sources agree) and, for taken domains, returns the most relevant details inline: SSL certificate, server IP, expiration date.

## MANDATORY READ — ANY DOMAIN-NAMING REQUEST

**As the very first action — before generating, recommending, suggesting, scoring, or curating ANY domain names — you MUST `Read references/naming_guide.md` in full.** Non-skippable. One Read tool call, ~3,300 words.

This rule fires on **all** of these triggers, not just on `suggest`:
- "schlag mir Domains vor", "suggest domains", "give me domain ideas"
- "good name for X", "guter Name für X", "creative domain names"
- "what should I call X", "wie soll ich X nennen"
- "Domain-Tipps", "domain tips", "naming ideas"
- bare `suggest` subcommand invocations
- any free-form follow-up where the user asks for a curated list of names

**The guide is the single source of truth. The Python `score_name()` heuristics are a sanity helper, NOT a substitute for the guide.** Skipping the guide produces generic `voicebotify` / `cloudhub` slop that doesn't match the user's actual project.

**Workflow for any naming request:**
1. `Read references/naming_guide.md` — non-skippable, before any candidate is written
2. Pick 2–3 patterns from the guide that fit the user's project (e.g. "AI phone bot" → Hybrid Neoclassic + Action-Verb + Made-up-Phonetic, NOT just `voicebot+ify`)
3. Hand-curate a candidate list using the guide's brainstorming techniques (semantic web, mood board, free association, grandma test, 1AM bar test)
4. Run `bulk` to check availability — `suggest` output is only a starting point, never the final list
5. Apply the don't-list (no hyphens, no digit substitutions, no false friends, no typo-squat distance ≤1)
6. Present 8–15 curated finalists with rationale + buy_links, not 200 raw heuristic outputs

## Requirements

**No dependencies. No venv. No pip/uv/pipx required.**

The entire skill runs on the **Python ≥ 3.11 standard library** (needed for `dict | None` syntax and `asyncio.to_thread`). Module imports used by the skill: `argparse, asyncio, dataclasses, datetime, hashlib, io, json, os, pathlib, re, secrets, socket, ssl, struct, sys, tempfile, time, typing, urllib`. All stdlib.

If you run an exotic Python build without the SSL module, only the `ssl` subcommand will fail; the rest still works.

## Quick Start

All commands are run from this skill's directory (the agent will cd there automatically). Same invocations on Linux, macOS, and Windows:

```bash
python3 scripts/domain_check.py check example.com
python3 scripts/domain_check.py bulk example.com example.org example.net
python3 scripts/domain_check.py ssl example.com
python3 scripts/domain_check.py resolve https://example.com/path
```

On Windows, use `python` instead of `python3` if needed.

## Subcommands

### `check <domain>`

Single-domain check, JSON output.

**For "Taken"** the response contains:
- `verdict: "Taken"`, `confidence`, `summary`
- `expiration_date` (ISO date) or `expiration_note` (e.g. "DENIC confirms the registration but does not expose the expiry date publicly (GDPR).")
- `registrar`, `nameservers`, `ip_addresses`
- `ssl: { issuer, subject, valid_to, days_until_expiry, fingerprint_sha256, ip_address, matches_hostname, ... }`
- `evidence: [...]` — list of all 5–6 sources with `source`/`strength`/`reason`

**For "Available"** a compact response: `verdict: "Available"`, `confidence`, `summary`, `evidence`. No SSL/IP blocks (irrelevant).

**For "Reserved"** / **"Unclear"**: `verdict` plus rationale in `summary` plus `evidence` for diagnosis.

### `bulk <d1> <d2> …` OR `--file <path>` OR `--stdin`

Up to 8 domains in parallel. NDJSON output (one line per domain) — pipe-friendly. Alternatives:
- `--format=json` → a single JSON array
- `--format=table` → human-readable table

```bash
python3 scripts/domain_check.py bulk --file domains.txt --format=table
echo -e "example.com\nexample.org" | python3 scripts/domain_check.py bulk --stdin
```

### `ssl <hostname> [--port 443]`

SSL certificate only. Returns issuer, subject, SAN, valid_from/to, days_until_expiry, SHA-256 fingerprint, protocol, cipher, and the effective IP of the TLS connection.

### `resolve <url-or-host>`

Extracts the hostname from a URL and resolves IPv4 + IPv6, plus reverse DNS for the first 3 IPs. Accepts `https://example.com/path`, `example.com:443`, `example.com`.

## What is the "TLD-aware decision tree"?

Whether a domain is "Available" or "Taken" depends on **which** sources are authoritative for the given TLD:

- **gTLDs** (`.com`, `.net`, `.io`, `.ai`, `.app`, `.pro`, `.club`, …): RDAP is mandatory under ICANN — RDAP no-object = 100% available.
- **GDPR ccTLDs** (`.de`, `.eu`, `.at`, `.ch`, `.es`, …): the registry typically redacts RDAP/WHOIS entirely. Here an **authoritative DNS NS lookup** against the registry NS (`a.nic.de`, `x.dns.eu`, …) yields a binary answer: NS records = registered, NXDOMAIN = available.
- **Unknown / reseller TLDs**: the WHOIS server is discovered live via `whois.iana.org` and cached persistently. If the response contains only disclaimers (no domain/registrar fields), the domain is treated heuristically as available.

## Edge Cases

- **IDN domains** (`münchen.de`): automatically converted to Punycode (`xn--mnchen-3ya.de`).
- **GDPR TLDs without expiry**: `expiration_date` is `null` and `expiration_note` explains why. This is correct behaviour, not a bug.
- **`.ch`/`.li`/`.es`**: registry WHOIS port 43 is blocked for anonymous IPs. The authoritative DNS NS lookup is the primary source here.
- **Rate limiting** (DENIC, AFNIC, SIDN): bulk concurrency is capped at 8; on HTTP 429 a single retry with short backoff is attempted.
- **IDNA failure**: invalid IDN inputs fall back to lowercase ASCII — no crash.

## Performance

- Single check: typically ~2–4 s (all 5 sources in parallel via asyncio).
- Bulk: 30 domains in ~10–15 s (concurrency 8, each domain again fans out per source).

## Architecture (for maintenance)

```
scripts/
├── domain_check.py          # CLI entry point, argparse subcommands
└── _lib/                    # importable Python package
    ├── tld_classifier.py    # TLD → GTLD_FULL / CCTLD_DSGVO / CCTLD_OPEN / UNKNOWN
    ├── rdap.py              # RDAP client with IANA bootstrap cache (24h)
    ├── whois_client.py      # WHOIS socket + 30+ TLD patterns + IANA discovery + heuristic fallback
    ├── auth_dns.py          # native UDP DNS resolver (RFC 1035) for TLD registry NS
    ├── presence.py          # DNS A/AAAA, HTTP/HTTPS, TLS cert with CN/SAN match
    ├── verdict.py           # decision tree: Available/Taken with confidence
    └── orchestrator.py      # async fan-out + user-friendly final report
```

Other skills can import the library modules directly:
```python
from _lib.orchestrator import check_domain
report = await check_domain("example.com")
```

## Naming Guide & Suggestion

The skill also helps you **come up with good names**, not just check existing ones.

### What makes a great domain name

Read **`references/naming_guide.md`** — a practical guide covering:

- The "type-once, no-spell-back" test
- Length sweet spots (top-100 sites average 6.2 chars)
- Phonetics: plosive consonants, vowel endings, alliteration, rhyme
- Naming patterns: real-word, compound, made-up, portmanteau, Hybrid Neoclassicism (Lumen, Nexus, GraphBase)
- TLD strategy with concrete matrix
- The AI-era twist: LLM citability, voice-agent discoverability
- Hard don't list: hyphens, digit swaps, false friends, typo-squats
- Real rebrand examples (Lyft, Flickr, Tumblr, Twilio…)
- A step-by-step **30-Minute Naming Workout** to run before generating candidates

### `suggest <seed> --use-case <type>`

Generate scored domain candidates from a seed keyword. Patterns: Greek/Latin roots, Hybrid Neoclassic, Suffix-Stack, Compound, Mutation, Action-Verb-Compound. Each candidate gets a 0.0–1.0 score from the heuristics in `_lib/naming.py` (length, syllables, phonetics, plosive starts, alliteration, trademark/typo-squat checks). Use cases: `tech_startup`, `ai_tool`, `dach_service`, `indie_saas`, `creative`, `developer`, `ecommerce_de`, `consumer_app`, `open_source`, `agency_dach`.

```bash
python3 scripts/domain_check.py suggest graph --use-case ai_tool --count 20
python3 scripts/domain_check.py suggest cloud --use-case indie_saas --check --check-top 5
```

The `--check` flag runs availability checks on the top candidates so you only see names that are actually buyable.

### `score <name>`

Score a single bare name (no TLD) and see the heuristic breakdown — useful when you already have an idea and want a sanity check.

```bash
python3 scripts/domain_check.py score lumenforge
```

The scorer is **a sanity helper, not the truth** — strong real brands like `zoom`, `slack`, `stripe` all live below 0.8 because the heuristics penalise short or low-vowel names. Use the score to spot obvious red flags (hyphens, digits, hard clusters), not as a gatekeeper.

## Resources

- `references/naming_guide.md` — what makes a great domain name (the creative side)
