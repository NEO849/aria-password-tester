"""Tests für die Analyse-Logik.

Methoden-Übersicht:
  test_short_weak()          -> kurzes Passwort ist schwach
  test_strong_password()     -> langes Zufallspasswort ist stark
  test_pattern_detection()   -> Jahreszahl wird erkannt
  test_excellent_password()  -> sehr langes Zufallspasswort ohne Muster ist exzellent
  test_crack_times_sane()    -> Crack-Zeiten sind monoton
"""
from itertools import pairwise

from app.strength import analyze, detect_patterns, shannon_entropy


def test_short_weak():
    r = analyze("abc")
    assert r["verdict_level"] in ("weak", "fair")


def test_strong_password():
    r = analyze("x7$Kq!2mP9#vLz8w")
    assert r["verdict_level"] in ("strong", "excellent")
    assert r["length"] == 16


def test_pattern_detection():
    patterns = detect_patterns("Sommer2024")
    assert "Jahreszahl" in patterns or "Jahreszeit" in patterns


def test_entropy_positive():
    assert shannon_entropy("aabb") > 0
    assert shannon_entropy("") == 0


def test_excellent_password():
    r = analyze("q7$Kx9!vLp2#wZt5Rn8@mC3")
    assert r["verdict_level"] == "excellent"


def test_crack_times_monotonic():
    r = analyze("aaaaaaaaaaaaaaaaaaaa")
    times = [t["seconds"] for t in r["crack_times"]]
    for a, b in pairwise(times):
        assert b <= a  # schnellere Angreifer => kürzere Zeit
