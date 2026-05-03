"""Domain-Name-Generator + Scoring-Engine.

Heuristiken aus 2025/2026 Research (Spaceship Psychology of Domain Names,
Pathak 2020 phonetics, Ehrenberg-Bass 2025 etymology trust, YC F25 batch analysis).

Zwei Hauptfunktionen:
  - score_name(name) -> dict   # 0.0-1.0 + breakdown per heuristic
  - generate(seed, use_case, n) -> list[Candidate]  # pattern-based generator
"""
from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from typing import Literal

VOWELS = set("aeiouy")
PLOSIVES = set("kptbdg")
# Common doubled consonants and digraphs are NOT clusters (e.g. doublings like 'll',
# 'ss', 'tt' or digraphs like 'ch', 'sh', 'th', 'ph'). We strip them first, then check
# for true 3+ consonant clusters.
_DOUBLES_AND_DIGRAPHS = re.compile(
    r"(ll|ss|tt|nn|mm|bb|dd|gg|pp|rr|ff|ck|ch|sh|th|ph|wh|qu|gh|kn|wr)",
    re.IGNORECASE,
)
HARD_CONSONANT_CLUSTERS = re.compile(r"[bcdfghjklmnpqrstvwxz]{3,}", re.IGNORECASE)


def _has_hard_cluster(name: str) -> bool:
    """True if name has 3+ true consonants in a row, ignoring doubles and common digraphs."""
    stripped = _DOUBLES_AND_DIGRAPHS.sub("X", name.lower())  # X = single placeholder consonant
    return bool(HARD_CONSONANT_CLUSTERS.search(stripped))


@dataclass
class ScoreBreakdown:
    score: float
    components: dict[str, float] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class Candidate:
    name: str
    pattern: str
    score: float
    breakdown: dict[str, float]
    pronunciation_hint: str | None = None


# ---------------------------------------------------------------------------
# Syllable counter (heuristic, language-agnostic; Pyphen-free)
# ---------------------------------------------------------------------------

def count_syllables(word: str) -> int:
    word = word.lower()
    if not word:
        return 0
    # group adjacent vowels into one cluster
    syl = 0
    prev_was_vowel = False
    for ch in word:
        is_vowel = ch in VOWELS
        if is_vowel and not prev_was_vowel:
            syl += 1
        prev_was_vowel = is_vowel
    # silent trailing 'e' ('Stripe' -> 1 syl, not 2)
    if word.endswith("e") and syl > 1 and not word.endswith(("le", "re")):
        syl -= 1
    return max(1, syl)


def vowel_consonant_ratio(word: str) -> float:
    word = re.sub(r"[^a-z]", "", word.lower())
    if not word:
        return 0.0
    vowels = sum(1 for c in word if c in VOWELS)
    return vowels / len(word)


# ---------------------------------------------------------------------------
# Scoring (additive heuristics; final clamped to [0, 1])
# ---------------------------------------------------------------------------

# Dictionary-based real-word check (best-effort, English).
_REAL_WORD_HINTS = {
    "apple", "square", "stripe", "zoom", "slack", "shop", "dock",
    "lumen", "nexus", "aurora", "atlas", "axis", "vector", "orbit",
    "vertex", "apex", "mantle", "forge", "helios", "nova", "prime",
    "loom", "bolt", "spark", "echo", "flux", "core", "edge", "node",
    "block", "stack", "wave", "pulse", "zone", "loop", "sync",
}

_TOP_BRAND_NAMES = {
    "google", "facebook", "apple", "amazon", "microsoft", "twitter",
    "instagram", "youtube", "tiktok", "linkedin", "snapchat", "spotify",
    "netflix", "uber", "airbnb", "stripe", "openai", "anthropic",
}


def score_name(name: str) -> ScoreBreakdown:
    """Score a bare domain name (no TLD) on 0.0-1.0 scale.
    Higher is better. Components are additive; final clamped.
    """
    n = name.lower().strip()
    parts: dict[str, float] = {}
    notes: list[str] = []

    if not re.fullmatch(r"[a-z0-9-]+", n):
        return ScoreBreakdown(0.0, {"invalid_chars": -1.0}, ["contains invalid characters"])

    length = len(n)
    syllables = count_syllables(n)

    # Length scoring — punchy short brands (Zoom, Slack, Stripe, Loom, Snap) get a bonus,
    # not a penalty, when they pair with 1 syllable (the "punchy" sweet spot).
    if length == 4 and syllables == 1:
        parts["length_punchy_short"] = 0.25
        notes.append("punchy 4-char 1-syllable brand (Zoom/Loom/Dock pattern)")
    elif length == 5 and syllables == 1:
        parts["length_punchy_short"] = 0.30
        notes.append("punchy 5-char 1-syllable brand (Slack/Stripe/Forge pattern)")
    elif 6 <= length <= 10:
        parts["length_optimal"] = 0.30
    elif 11 <= length <= 14:
        parts["length_acceptable"] = 0.15
    elif 15 <= length <= 17:
        parts["length_borderline"] = 0.05
    elif length < 4:
        parts["length_too_short"] = -0.20
        notes.append(f"length {length} too short to be brandable")
    else:
        parts["length_penalty"] = -0.30
        notes.append(f"length {length} too long — type-once test fails")

    # Syllables — 2-3 is sweet spot; 1 syllable only "good" if length is also short (covered above).
    if 2 <= syllables <= 3:
        parts["syllables_optimal"] = 0.20
    elif syllables == 1:
        parts["syllables_acceptable"] = 0.10  # OK for punchy short, neutral otherwise
    elif syllables == 4:
        parts["syllables_acceptable"] = 0.05
    else:
        parts["syllables_penalty"] = -0.25
        notes.append(f"{syllables} syllables — hard to memorize")

    vc = vowel_consonant_ratio(n)
    if 0.30 <= vc <= 0.50:
        parts["vowel_ratio_ideal"] = 0.15
    else:
        parts["vowel_ratio_off"] = -0.10

    if n[0] in PLOSIVES:
        parts["plosive_start"] = 0.10
        notes.append("plosive start (recall boost)")

    if n[-1] in VOWELS or n.endswith("y"):
        parts["vowel_ending"] = 0.05

    if _has_hard_cluster(n):
        parts["consonant_cluster"] = -0.20
        notes.append("3+ true consonant cluster — pronunciation risk")

    if "-" in n:
        parts["hyphen"] = -0.40
        notes.append("hyphen kills word-of-mouth")
    if any(c.isdigit() for c in n):
        parts["digit"] = -0.30
        notes.append("digits cause spelling confusion")

    # Real word boost
    if n in _REAL_WORD_HINTS:
        parts["real_word"] = 0.10
        notes.append("real dictionary word")

    # Suffix-stack pattern boost
    if re.search(r"(ly|ify|io|hub|kit|lab)$", n):
        parts["suffix_stack"] = 0.10

    # Action verb (1 syllable, plosive start)
    if syllables == 1 and n[0] in PLOSIVES and length <= 6:
        parts["action_verb_punchy"] = 0.10

    # Alliteration heuristic for 2-word compounds
    halves = _split_compound(n)
    if halves and halves[0][0] == halves[1][0]:
        parts["alliteration"] = 0.15
        notes.append(f"alliteration ({halves[0]}+{halves[1]})")

    # Trademark / brand collision
    if n in _TOP_BRAND_NAMES:
        parts["trademark_hit"] = -0.50
        notes.append("matches well-known trademark — avoid")
    elif _is_typosquat(n):
        parts["typosquat"] = -0.50
        notes.append("looks like typo of major brand")

    raw = sum(parts.values())
    score = max(0.0, min(1.0, raw))
    return ScoreBreakdown(score=score, components=parts, notes=notes)


def _split_compound(name: str) -> tuple[str, str] | None:
    """Crude split: try common boundaries (hub|box|kit|lab|app|io|fy)."""
    for marker in ("hub", "box", "kit", "lab", "app", "fy", "ly"):
        if name.endswith(marker) and len(name) > len(marker) + 2:
            return name[:-len(marker)], marker
    return None


def _is_typosquat(name: str) -> bool:
    for brand in _TOP_BRAND_NAMES:
        if abs(len(name) - len(brand)) <= 1 and _levenshtein(name, brand) == 1:
            return True
    return False


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


# ---------------------------------------------------------------------------
# TLD recommendation matrix
# ---------------------------------------------------------------------------

TldUseCase = Literal[
    "tech_startup", "ai_tool", "dach_service", "indie_saas",
    "creative", "developer", "ecommerce_de", "consumer_app",
    "open_source", "agency_dach",
]

TLD_MATRIX: dict[TldUseCase, dict[str, list[str]]] = {
    "tech_startup":  {"primary": ["com"],          "secondary": ["io", "dev"],     "avoid": ["biz", "info", "xyz"]},
    "ai_tool":       {"primary": ["ai"],           "secondary": ["com"],           "avoid": ["ml", "tech"]},
    "dach_service":  {"primary": ["de"],           "secondary": ["com", "at", "ch"], "avoid": ["biz", "eu"]},
    "indie_saas":    {"primary": ["com"],          "secondary": ["app", "io"],     "avoid": ["biz", "online"]},
    "creative":      {"primary": ["studio", "design"], "secondary": ["com", "me"], "avoid": ["biz"]},
    "developer":     {"primary": ["dev"],          "secondary": ["me", "io"],      "avoid": ["biz"]},
    "ecommerce_de":  {"primary": ["de"],           "secondary": ["shop", "com"],   "avoid": ["store", "online"]},
    "consumer_app":  {"primary": ["com"],          "secondary": ["app"],           "avoid": ["tech", "xyz"]},
    "open_source":   {"primary": ["dev", "io"],    "secondary": ["org"],           "avoid": ["com"]},
    "agency_dach":   {"primary": ["de"],           "secondary": ["agency", "com"], "avoid": ["biz"]},
}


# ---------------------------------------------------------------------------
# Generator patterns
# ---------------------------------------------------------------------------

_GREEK_LATIN_ROOTS = [
    "lumen", "nexus", "aurora", "atlas", "axis", "vector", "orbit",
    "vertex", "apex", "mantle", "forge", "helios", "nova", "prime",
    "lemma", "locus", "sanctum", "velox", "stratus", "aether",
]

_TECH_NOUNS = [
    "graph", "node", "core", "edge", "cloud", "stack", "loop", "wave",
    "flow", "path", "base", "hub", "lab", "kit", "box", "deck", "thread",
]

_SUFFIXES_TECH = ["ly", "ify", "io", "r", "hub", "kit", "lab", "able"]

_ACTION_VERBS = ["zoom", "ship", "spark", "loop", "sync", "dash", "shift", "leap", "spin"]


def generate_candidates(
    seed: str,
    use_case: TldUseCase = "tech_startup",
    n: int = 60,
) -> list[Candidate]:
    """Generate candidate names from a seed keyword.

    Patterns covered:
      - Greek/Latin solo
      - Hybrid Neoclassic (greek_root + tech_noun)
      - Suffix-Stack (seed + suffix)
      - Compound (seed + tech_noun)
      - Mutation (seed -1 vowel)
      - Made-up (seed[0] + greek_root[1:])
    """
    seed = re.sub(r"[^a-z]", "", seed.lower())
    out: list[Candidate] = []

    # 1. Greek/Latin solo
    for root in _GREEK_LATIN_ROOTS:
        out.append(Candidate(root, "greek_latin_root", 0.0, {}))

    # 2. Hybrid Neoclassic
    for root, noun in itertools.product(_GREEK_LATIN_ROOTS[:8], _TECH_NOUNS[:8]):
        out.append(Candidate(f"{root}{noun}", "hybrid_neoclassic", 0.0, {}))

    # 3. Suffix-Stack
    for suffix in _SUFFIXES_TECH:
        out.append(Candidate(f"{seed}{suffix}", "suffix_stack", 0.0, {}))

    # 4. Compound (seed + tech_noun)
    for noun in _TECH_NOUNS:
        out.append(Candidate(f"{seed}{noun}", "compound", 0.0, {}))
        out.append(Candidate(f"{noun}{seed}", "compound_reversed", 0.0, {}))

    # 5. Mutation (drop one vowel)
    if seed:
        for i, ch in enumerate(seed):
            if ch in VOWELS and len(seed) > 4:
                mut = seed[:i] + seed[i + 1:]
                out.append(Candidate(mut, "mutation_drop_vowel", 0.0, {}))

    # 6. Action verb compound
    for verb in _ACTION_VERBS:
        out.append(Candidate(f"{seed}{verb}", "action_verb_compound", 0.0, {}))

    # Score + sort + dedupe
    seen: set[str] = set()
    scored: list[Candidate] = []
    for cand in out:
        if cand.name in seen or len(cand.name) < 4 or len(cand.name) > 18:
            continue
        seen.add(cand.name)
        breakdown = score_name(cand.name)
        cand.score = breakdown.score
        cand.breakdown = breakdown.components
        cand.pronunciation_hint = "-".join(_syllabify(cand.name))
        scored.append(cand)

    scored.sort(key=lambda c: c.score, reverse=True)
    return scored[:n]


def _syllabify(name: str) -> list[str]:
    """Crude visual syllabification for pronunciation hints."""
    syl: list[str] = []
    current = ""
    for i, ch in enumerate(name):
        current += ch
        if ch in VOWELS and i + 1 < len(name) and name[i + 1] not in VOWELS:
            if i + 2 < len(name) and name[i + 2] in VOWELS:
                syl.append(current)
                current = ""
    if current:
        syl.append(current)
    return syl or [name]


def recommend_tlds(use_case: TldUseCase) -> dict[str, list[str]]:
    return TLD_MATRIX.get(use_case, TLD_MATRIX["tech_startup"])
