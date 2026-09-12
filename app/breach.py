"""Have-I-Been-Pwned-Abgleich per k-Anonymity (Passwort verlässt nie den Server).

Methoden-Übersicht:
  check_breach(password)  -> (breached: bool, count: int) oder (None, None) bei Fehler
"""
import hashlib

import httpx

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def check_breach(password: str, timeout: float = 5.0) -> tuple[bool | None, int | None]:
    """Fragt HIBP per SHA1-Präfix ab. Es wird nur der 5-stellige Präfix gesendet."""
    if not password:
        return None, None
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.get(HIBP_RANGE_URL.format(prefix=prefix))
            r.raise_for_status()
        for line in r.text.splitlines():
            parts = line.split(":")
            if len(parts) != 2:
                continue
            if parts[0].strip().upper() == suffix:
                try:
                    return True, int(parts[1].strip())
                except ValueError:
                    return True, 0
        return False, 0
    except httpx.HTTPError:
        return None, None
