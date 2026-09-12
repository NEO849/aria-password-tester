"""Kernlogik: Entropie, Mustererkennung, Crack-Zeit-Schätzung, Bewertung.

Methoden-Übersicht:
  shannon_entropy(pw)          -> Shannon-Entropie in Bits
  detect_patterns(pw)          -> erkennt schwache Muster
  estimate_crack_times(pw)     -> Schätzungen gegen mehrere Angreifer
  humanize_seconds(sec)        -> Sekunden in lesbare Zeit
  zxcvbn_result(pw)            -> Wrapper um zxcvbn
  analyze(pw)                  -> Gesamtanalyse als Dict
"""
import math
import re

from zxcvbn import zxcvbn

PATTERNS = [
    (r"(19|20)\d{2}", "Jahreszahl"),
    (r"(?i)(januar|februar|märz|april|mai|juni|juli|august|september|oktober|november|dezember)", "Monat"),
    (r"(?i)(sommer|winter|frühling|herbst)", "Jahreszeit"),
    (r"(?i)(qwertz|qwerty|asdf|yxcv|1234)", "Keyboard-Muster"),
    (r"(.)\1{2,}", "Zeichenwiederholung"),
    (r"^[a-z]+$", "Nur Kleinbuchstaben"),
    (r"^[A-Z]+$", "Nur Großbuchstaben"),
    (r"^[0-9]+$", "Nur Ziffern"),
    (r"(?i)(passwort|password|admin|willkommen|welcome|letmein|geheim)", "Trivialwort"),
    (r"^[A-Z][a-z]+\d{1,4}[!?]?$", "Name+Zahl (häufiges Schema)"),
]


def shannon_entropy(pw: str) -> float:
    """Shannon-Entropie pro Zeichen (Bits)."""
    if not pw:
        return 0.0
    freq: dict[str, int] = {}
    for ch in pw:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / len(pw)) * math.log2(c / len(pw)) for c in freq.values())


def charset_size(pw: str) -> int:
    """Größe des verwendeten Zeichenvorrats."""
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"[0-9]", pw):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        size += 33
    return size or 1


def detect_patterns(pw: str) -> list[str]:
    """Erkennt schwache Muster."""
    return [label for regex, label in PATTERNS if re.search(regex, pw)]


def humanize_seconds(sec: float) -> str:
    """Formatiert Sekunden menschenlesbar."""
    if sec < 1:
        return "sofort"
    if sec < 60:
        return f"{sec:.0f} Sekunden"
    if sec < 3600:
        return f"{sec / 60:.0f} Minuten"
    if sec < 86400:
        return f"{sec / 3600:.0f} Stunden"
    if sec < 86400 * 365:
        return f"{sec / 86400:.0f} Tage"
    if sec < 86400 * 365 * 100:
        return f"{sec / (86400 * 365):.0f} Jahre"
    if sec < 86400 * 365 * 1e6:
        return f"{sec / (86400 * 365 * 1000):.0f} Jahrtausende"
    return "praktisch unendlich"


def estimate_crack_times(pw: str) -> list[dict]:
    """Schätzt Crack-Zeiten gegen verschiedene Angreifer-Profile."""
    size = charset_size(pw)
    combos = size ** max(len(pw), 1)
    half = combos / 2  # Erwartungswert: halbe Suche

    profiles = [
        ("Online-Angriff (100/s)",        100),
        ("GPU-Cluster RTX 4090 (1M/s)",   1_000_000),
        ("GPU-Cluster 8x RTX 4090 (8M/s)", 8_000_000),
        ("Hypothetischer ASIC-Angriff (1B/s)", 1_000_000_000),
    ]
    return [
        {
            "attacker": name,
            "seconds": half / rate,
            "human": humanize_seconds(half / rate),
        }
        for name, rate in profiles
    ]


def zxcvbn_result(pw: str) -> dict:
    """Wrapper um zxcvbn: Score, Feedback, Guess-Zeit."""
    r = zxcvbn(pw)
    feedback = r.get("feedback", {}) or {}
    suggestions = feedback.get("suggestions", []) or []
    warning = feedback.get("warning")
    if warning:
        suggestions.insert(0, warning)
    return {
        "score": r.get("score", 0),
        "suggestions": suggestions,
        "guesses": r.get("guesses", 0),
    }


def verdict(score: int, length: int, patterns: list[str]) -> tuple[str, str]:
    """Liefert Klartext-Bewertung und Level."""
    if length < 8 or score <= 1:
        return "Sehr schwach: sofort ändern", "weak"
    if length < 12 or score == 2:
        return "Schwach: Ausbau empfohlen", "fair"
    if patterns:
        return f"Mittelmäßig, Muster erkannt: {', '.join(patterns[:2])}", "fair"
    if score == 4 and length >= 20:
        return "Exzellent: praktisch nicht brute-forcebar", "excellent"
    if score == 3 and length >= 14:
        return "Gut: solide Basis", "good"
    if score == 4 and length >= 16:
        return "Sehr stark: robust gegen Standardangriffe", "strong"
    if score == 4:
        return "Stark", "strong"
    return "Okay, aber ausbaufähig", "good"


def analyze(pw: str) -> dict:
    """Gesamtanalyse als Dict (ohne HIBP — das macht breach.py)."""
    z = zxcvbn_result(pw)
    patterns = detect_patterns(pw)
    v_text, v_level = verdict(z["score"], len(pw), patterns)
    return {
        "length": len(pw),
        "entropy_bits": round(shannon_entropy(pw) * len(pw), 1),
        "zxcvbn_score": z["score"],
        "patterns": patterns,
        "feedback": z["suggestions"],
        "crack_times": estimate_crack_times(pw),
        "verdict": v_text,
        "verdict_level": v_level,
    }
