"""Pydantic-Schemas für Request und Response.

Methoden-Übersicht:
  AnalyzeRequest   -> Eingabe (Passwort)
  AnalyzeResponse  -> strukturierte Antwort mit allen Analyse-Feldern
"""
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    """Anfrage-Body für /api/analyze."""
    password: str = Field(..., min_length=1, max_length=512)


class CrackTime(BaseModel):
    """Geschätzte Zeit gegen einen Angreifer-Typ."""
    attacker: str
    seconds: float
    human: str


class AnalyzeResponse(BaseModel):
    """Antwort von /api/analyze."""
    length: int
    entropy_bits: float
    zxcvbn_score: int
    patterns: list[str]
    feedback: list[str]
    crack_times: list[CrackTime]
    breached: bool | None
    breach_count: int | None
    verdict: str
    verdict_level: str  # "weak" | "fair" | "good" | "strong" | "excellent"
